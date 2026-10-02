import { get, put, BlobNotFoundError, BlobPreconditionFailedError } from '@vercel/blob';
import { createHash } from 'node:crypto';
import { AppError, authenticate, issueSession, verifyPassword, snapshot, mutate } from '../lib/domain.js';

const STATE='state.json';
async function read(path){try{const r=await get(path,{access:'private',useCache:false});if(!r||r.statusCode!==200)return null;return {data:await new Response(r.stream).json(),etag:r.blob.etag};}catch(e){if(e instanceof BlobNotFoundError)return null;throw e}}
async function write(path,data,etag){return put(path,JSON.stringify(data),{access:'private',addRandomSuffix:false,contentType:'application/json',...(etag?{allowOverwrite:true,ifMatch:etag}:{allowOverwrite:false})})}
function cookie(token){return `agenda_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${token?604800:0}`}
function tokenOf(req){return (req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('agenda_session='))?.slice(15)||''}
async function throttle(req,email){
  const ip=String(req.headers['x-vercel-forwarded-for']||req.headers['x-forwarded-for']||req.socket?.remoteAddress||'unknown').split(',')[0];
  const key=createHash('sha256').update(ip+'|'+email).digest('hex');const path='rate/'+key+'.json';
  for(let n=0;n<4;n++){const previous=await read(path);const now=Date.now();const data=previous?.data?.until>now?previous.data:{count:0,until:now+15*60*1000};if(data.count>=8)throw new AppError(429,'Demasiados intentos. Espera 15 minutos antes de volver a entrar.');data.count++;try{await write(path,data,previous?.etag);return;}catch(e){if(e instanceof BlobPreconditionFailedError||/already exists/i.test(e.message))continue;throw e;}}
  throw new AppError(429,'Espera un momento y vuelve a intentar.');
}
export default async function handler(req,res){
  res.setHeader('Cache-Control','private, no-store');res.setHeader('X-Content-Type-Options','nosniff');
  try{
    if(!['GET','POST'].includes(req.method)){res.setHeader('Allow','GET, POST');throw new AppError(405,'Método no permitido.');}
    if(req.method==='POST'){
      const origin=req.headers.origin;if(origin&&new URL(origin).host!==req.headers.host)throw new AppError(403,'Origen no permitido.');
      if(!String(req.headers['content-type']||'').startsWith('application/json'))throw new AppError(415,'Usa una solicitud JSON.');
      if(Number(req.headers['content-length']||0)>16384)throw new AppError(413,'El formulario es demasiado grande.');
    }
    const b=req.method==='POST'?(typeof req.body==='string'?JSON.parse(req.body):req.body):{};
    if(req.method==='POST'&&(!b||typeof b!=='object'||Array.isArray(b)))throw new AppError(400,'Solicitud inválida.');
    const loaded=await read(STATE);if(!loaded)throw new AppError(503,'El guardado está preparando sus cuentas. Intenta nuevamente en un momento.');
    if(b.action==='login'){
      const email=String(b.email||'').trim().toLowerCase();if(email.length>254||typeof b.password!=='string'||b.password.length>256)throw new AppError(400,'Revisa el correo y la contraseña.');
      await throttle(req,email);
      const a=loaded.data.accounts.find(a=>a.email===email);
      if(!a||!verifyPassword(b.password,a.credentials))throw new AppError(401,'Correo o contraseña incorrectos.');
      res.setHeader('Set-Cookie',cookie(issueSession(loaded.data,a)));return res.status(200).json(snapshot(loaded.data,a));
    }
    const token=tokenOf(req);let account=authenticate(loaded.data,token);
    if(req.method==='GET')return res.status(200).json(snapshot(loaded.data,account));
    let base=loaded;
    for(let n=0;n<4;n++){
      account=authenticate(base.data,token);mutate(base.data,account,b);
      try{await write(STATE,base.data,base.etag);if(b.action==='logout')res.setHeader('Set-Cookie',cookie(''));return res.status(200).json(b.action==='logout'?{ok:true}:snapshot(base.data,account));}
      catch(e){if(!(e instanceof BlobPreconditionFailedError))throw e;base=await read(STATE);if(!base)throw new AppError(503,'El guardado no está disponible.');}
    }
    throw new AppError(409,'Hubo otro cambio al mismo tiempo. Vuelve a intentar.');
  }catch(e){
    if(e instanceof AppError)return res.status(e.status).json({error:e.message});
    if(e instanceof SyntaxError)return res.status(400).json({error:'El formulario no es válido.'});
    console.error('Agenda request failed:',e.name);
    return res.status(503).json({error:'No se pudo conectar con el guardado. Tus cambios no se han confirmado; vuelve a intentar.'});
  }
}
