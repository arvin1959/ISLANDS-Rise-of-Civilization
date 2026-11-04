import express from 'express';
import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, timingSafeEqual, createHmac } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const ROOT=path.resolve(__dirname,'..');
const PORT=Number(process.env.PORT||3000), SECRET=process.env.SESSION_SECRET||'change-this-secret-before-deploy-please';
const db=new DatabaseSync(process.env.DB_PATH||path.join(ROOT,'world.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS players(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,character_name TEXT NOT NULL,island INTEGER NOT NULL UNIQUE,created_at TEXT DEFAULT CURRENT_TIMESTAMP,last_online TEXT);
CREATE TABLE IF NOT EXISTS world(id INTEGER PRIMARY KEY CHECK(id=1),state TEXT NOT NULL);`);
const initial={resources:[{wood:35,stone:22,food:18,fish:5},{wood:35,stone:22,food:18,fish:5}],buildings:[[],[]],nodes:[Array.from({length:13},(_,i)=>({kind:i%4===0?'stone':i%4===1?'wood':i%4===2?'food':'fish',amount:i%4===0?4:5})),Array.from({length:13},(_,i)=>({kind:i%4===0?'stone':i%4===1?'wood':i%4===2?'food':'fish',amount:i%4===0?4:5}))],discovered:[[0],[1]],ships:[],population:[1,1],positions:[{x:0,z:0},{x:0,z:0}],chat:[]};
if(!db.prepare('SELECT id FROM world WHERE id=1').get())db.prepare('INSERT INTO world(id,state) VALUES(1,?)').run(JSON.stringify(initial));
const getWorld=()=>JSON.parse(db.prepare('SELECT state FROM world WHERE id=1').get().state);
const saveWorld=w=>db.prepare('UPDATE world SET state=? WHERE id=1').run(JSON.stringify(w));
const hash=p=>{const salt=randomBytes(16).toString('hex');return salt+':'+scryptSync(p,salt,64).toString('hex')};
const verify=(p,h)=>{try{const [salt,key]=h.split(':');return timingSafeEqual(scryptSync(p,salt,64),Buffer.from(key,'hex'))}catch{return false}};
const sign=id=>{const body=Buffer.from(JSON.stringify({id,exp:Date.now()+30*864e5})).toString('base64url');return body+'.'+createHmac('sha256',SECRET).update(body).digest('base64url')};
const unsign=t=>{try{const [b,s]=t.split('.');const good=createHmac('sha256',SECRET).update(b).digest();if(!timingSafeEqual(good,Buffer.from(s,'base64url')))return null;const d=JSON.parse(Buffer.from(b,'base64url'));return d.exp>Date.now()?d.id:null}catch{return null}};
const parseCookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2));
const playerFor=req=>{const id=unsign(parseCookies(req).islands_session||'');return id?db.prepare('SELECT id,username,character_name,island FROM players WHERE id=?').get(id):null};
const app=express();app.use(express.json({limit:'32kb'}));
app.get('/api/status',(req,res)=>{const players=db.prepare('SELECT id,username,character_name,island,last_online FROM players ORDER BY id').all();res.json({count:players.length,players:players.map(p=>({...p,online:online.has(p.id)})),me:playerFor(req)});});
app.post('/api/register',(req,res)=>{const username=String(req.body.username||'').trim(),password=String(req.body.password||''),character=String(req.body.character||username).trim();if(!/^[\p{L}\p{N}_-]{3,18}$/u.test(username)||password.length<8||password.length>100||character.length<2||character.length>18)return res.status(400).json({error:'نام کاربری ۳ تا ۱۸ نویسه و گذرواژه حداقل ۸ نویسه باشد.'});try{const add=db.prepare('INSERT INTO players(username,password_hash,character_name,island) VALUES(?,?,?,?)');const tx=db.transaction(()=>{const count=db.prepare('SELECT COUNT(*) n FROM players').get().n;if(count>=2)throw Error('ظرفیت دو حساب این جهان تکمیل شده است.');const island=count;const result=add.run(username,hash(password),character,island);return Number(result.lastInsertRowid)});const id=tx();res.setHeader('Set-Cookie',`islands_session=${encodeURIComponent(sign(id))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`);res.json({ok:true});}catch(e){res.status(409).json({error:e.message.includes('UNIQUE')?'این نام کاربری قبلاً انتخاب شده است.':e.message})}});
app.post('/api/login',(req,res)=>{const p=db.prepare('SELECT * FROM players WHERE username=?').get(String(req.body.username||'').trim());if(!p||!verify(String(req.body.password||''),p.password_hash))return res.status(401).json({error:'نام کاربری یا گذرواژه درست نیست.'});db.prepare('UPDATE players SET last_online=CURRENT_TIMESTAMP WHERE id=?').run(p.id);res.setHeader('Set-Cookie',`islands_session=${encodeURIComponent(sign(p.id))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`);res.json({ok:true})});
app.post('/api/logout',(req,res)=>{res.setHeader('Set-Cookie','islands_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');res.json({ok:true})});
app.get('/api/world',(req,res)=>{const me=playerFor(req);if(!me)return res.status(401).json({error:'ابتدا وارد جهان شو.'});res.json({me,world:getWorld(),players:db.prepare('SELECT id,username,character_name,island FROM players').all()})});
app.use(express.static(path.join(ROOT,'dist')));app.get('*',(req,res)=>res.sendFile(path.join(ROOT,'dist','index.html')));
const server=createServer(app),wss=new WebSocketServer({noServer:true}),online=new Map();
server.on('upgrade',(req,socket,head)=>{if(req.url!=='/ws'){socket.destroy();return;}const id=unsign(parseCookies(req).islands_session||'');if(!id||!db.prepare('SELECT id FROM players WHERE id=?').get(id)){socket.destroy();return;}wss.handleUpgrade(req,socket,head,ws=>{ws.playerId=id;wss.emit('connection',ws,req)})});
const broadcast=(data,except)=>{const raw=JSON.stringify(data);for(const c of wss.clients)if(c.readyState===1&&c!==except)c.send(raw)};
const send=(ws,type,data)=>ws.send(JSON.stringify({type,data}));
const allowedCosts={hut:{wood:18,stone:4},campfire:{wood:8,stone:6},storehouse:{wood:24,stone:12},farm:{wood:14,stone:5},workbench:{wood:12,stone:8},watchtower:{wood:20,stone:18}};
const clamp=(n,a,b)=>Math.max(a,Math.min(b,n));
wss.on('connection',(ws)=>{const p=db.prepare('SELECT id,username,character_name,island FROM players WHERE id=?').get(ws.playerId);online.set(p.id,ws);db.prepare('UPDATE players SET last_online=CURRENT_TIMESTAMP WHERE id=?').run(p.id);send(ws,'welcome',{me:p,world:getWorld(),players:db.prepare('SELECT id,username,character_name,island FROM players').all(),online:[...online.keys()]});broadcast({type:'presence',data:{id:p.id,online:true,character:p.character_name}} ,ws);
ws.on('message',buf=>{let msg;try{msg=JSON.parse(buf.toString())}catch{return}const w=getWorld(),i=p.island;
if(msg.type==='move'){const x=clamp(Number(msg.x)||0,-4.8,4.8),z=clamp(Number(msg.z)||0,-4.2,4.2);if(Math.hypot(x-w.positions[i].x,z-w.positions[i].z)>4)return;w.positions[i]={x,z};saveWorld(w);broadcast({type:'move',data:{id:p.id,island:i,x,z}},ws)}
if(msg.type==='gather'){const kind=String(msg.kind);if(!['wood','stone','food','fish'].includes(kind))return;const node=msg.node;if(!Number.isInteger(node)||node<0||node>1000)return;const nodes=w.nodes[i];if(nodes[node]?.depleted)return;if(!nodes[node])nodes[node]={kind,amount:kind==='wood'?5:kind==='stone'?4:3};if(nodes[node].kind!==kind||nodes[node].amount<=0)return;const amount=Math.min(3,nodes[node].amount);nodes[node].amount-=amount;if(!nodes[node].amount)nodes[node].depleted=true;w.resources[i][kind]+=amount;saveWorld(w);broadcast({type:'world',data:w});send(ws,'notice',{text:`${amount} واحد ${kind==='wood'?'چوب':kind==='stone'?'سنگ':kind==='food'?'خوراک':'ماهی'} جمع‌آوری شد.`})}
if(msg.type==='build'){const type=String(msg.building),cost=allowedCosts[type];if(!cost)return;const x=clamp(Number(msg.x)||0,-5,5),z=clamp(Number(msg.z)||0,-5,5);if(Math.hypot(x,z)>5)return;if(w.buildings[i].length>=80)return;if(w.buildings[i].some(b=>Math.hypot(b.x-x,b.z-z)<1.25))return send(ws,'notice',{text:'این محل با ساختمان دیگری تداخل دارد.'});for(const k in cost)if(w.resources[i][k]<cost[k])return send(ws,'notice',{text:'منابع کافی نیست.'});for(const k in cost)w.resources[i][k]-=cost[k];w.buildings[i].push({id:randomBytes(5).toString('hex'),type,x,z,level:1,owner:p.id});if(type==='hut')w.population[i]++;saveWorld(w);broadcast({type:'world',data:w});send(ws,'notice',{text:'ساختمان با موفقیت ساخته شد.'})}
if(msg.type==='chat'){const text=String(msg.text||'').trim().slice(0,180);if(!text)return;const item={id:randomBytes(4).toString('hex'),name:p.character_name,text,at:Date.now()};w.chat.push(item);w.chat=w.chat.slice(-40);saveWorld(w);broadcast({type:'chat',data:item})}
});ws.on('close',()=>{if(online.get(p.id)===ws)online.delete(p.id);broadcast({type:'presence',data:{id:p.id,online:false,character:p.character_name}})})});
server.listen(PORT,()=>console.log(`ISLANDS server listening on ${PORT}`));
