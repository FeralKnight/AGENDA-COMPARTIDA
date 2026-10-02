import { createHmac, timingSafeEqual, scryptSync, randomUUID } from 'node:crypto';

export class AppError extends Error { constructor(status,message){super(message);this.status=status;} }
export const permissionKeys=['createClients','editClients','deleteClients','createEvents','editEvents','deleteEvents'];
export const can=(account,key)=>account.role==='admin'||account.permissions?.[key]===true;
export const safeAccount=a=>({id:a.id,name:a.name,theme:a.theme,role:a.role,permissions:a.permissions,preferences:a.preferences});
export function snapshot(state,account){return {revision:state.revision,me:safeAccount(account),accounts:state.accounts.map(a=>({...safeAccount(a),...(account.role==='admin'?{email:a.email}:{})})),clients:state.clients.filter(c=>!c.deletedAt),events:state.events.filter(e=>!e.deletedAt)}}
export function verifyPassword(password,credentials){if(typeof password!=='string'||password.length>256)return false;const expected=Buffer.from(credentials.hash,'hex');const actual=scryptSync(password,credentials.salt,64);return expected.length===actual.length&&timingSafeEqual(expected,actual)}
export function issueSession(state,a){const data=Buffer.from(JSON.stringify({uid:a.id,v:a.authVersion,exp:Date.now()+7*24*60*60*1000})).toString('base64url');return data+'.'+createHmac('sha256',state.sessionSecret).update(data).digest('base64url')}
export function authenticate(state,token){try{if(typeof token!=='string'||token.length>1000)throw 0;const [data,signature,extra]=token.split('.');if(extra)throw 0;const expected=createHmac('sha256',state.sessionSecret).update(data).digest();const actual=Buffer.from(signature,'base64url');if(actual.length!==expected.length||!timingSafeEqual(actual,expected))throw 0;const p=JSON.parse(Buffer.from(data,'base64url').toString());const a=state.accounts.find(a=>a.id===p.uid);if(!a||p.exp<Date.now()||p.v!==a.authVersion)throw 0;return a;}catch{throw new AppError(401,'Inicia sesión para acceder a la agenda.')}}
function text(value,label,max,required=false){if(typeof value!=='string')throw new AppError(400,`${label}: valor inválido.`);const out=value.trim();if(out.length>max||(required&&!out))throw new AppError(400,`Revisa ${label.toLowerCase()}.`);return out}
function current(list,id,version){const row=list.find(r=>r.id===id&&!r.deletedAt);if(!row)throw new AppError(404,'El registro ya no está disponible.');if(row.version!==version)throw new AppError(409,'Este registro cambió en otra cuenta. Actualiza la vista y vuelve a editarlo.');return row}
export function mutate(state,a,b){
  const now=new Date().toISOString();
  const requirePermission=key=>{if(!can(a,key))throw new AppError(403,'Tu cuenta no tiene permiso para realizar este cambio.')};
  if(b.action==='saveClient'){
    requirePermission(b.id?'editClients':'createClients');
    const item={name:text(b.name,'Nombre',100,true),phone:text(b.phone??'','Teléfono',40),notes:text(b.notes??'','Notas',1000)};
    if(b.id){const row=current(state.clients,b.id,b.version);Object.assign(row,item,{version:row.version+1,updatedAt:now,updatedBy:a.id});}
    else state.clients.push({...item,id:randomUUID(),version:1,createdAt:now,createdBy:a.id,updatedAt:now});
  }else if(b.action==='saveEvent'){
    requirePermission(b.id?'editEvents':'createEvents');
    if(!state.clients.some(c=>c.id===b.client&&!c.deletedAt))throw new AppError(400,'Selecciona un cliente registrado.');
    if(!state.accounts.some(u=>u.id===b.owner))throw new AppError(400,'Selecciona un responsable.');
    if(typeof b.date!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(b.date)||!Number.isFinite(Date.parse(b.date+'T12:00:00Z'))||new Date(b.date+'T12:00:00Z').toISOString().slice(0,10)!==b.date)throw new AppError(400,'Revisa la fecha.');
    if(typeof b.time!=='string'||!/^([01]\d|2[0-3]):[0-5]\d$/.test(b.time))throw new AppError(400,'Revisa la hora.');
    if(!['Pedido','Entrega','Visita'].includes(b.type)||typeof b.done!=='boolean')throw new AppError(400,'Revisa el tipo y estado de la cita.');
    const item={client:b.client,title:text(b.title,'Descripción',120,true),date:b.date,time:b.time,type:b.type,owner:b.owner,notes:text(b.notes??'','Notas',1000),done:b.done};
    if(b.id){const row=current(state.events,b.id,b.version);Object.assign(row,item,{version:row.version+1,updatedAt:now,updatedBy:a.id});}
    else state.events.push({...item,id:randomUUID(),version:1,createdAt:now,createdBy:a.id,updatedAt:now});
  }else if(b.action==='deleteEvent'||b.action==='deleteClient'){
    const isClient=b.action==='deleteClient';requirePermission(isClient?'deleteClients':'deleteEvents');
    if(isClient&&state.events.some(e=>e.client===b.id&&!e.deletedAt))throw new AppError(409,'Este cliente tiene citas. Conserva su ficha o elimina primero las citas.');
    const row=current(isClient?state.clients:state.events,b.id,b.version);row.deletedAt=now;row.deletedBy=a.id;row.version++;
  }else if(b.action==='preferences'){
    const p=b.preferences;
    if(!p||typeof p.light!=='boolean'||typeof p.characters!=='boolean'||typeof p.color!=='string'||!/^#[0-9a-fA-F]{6}$/.test(p.color))throw new AppError(400,'Revisa la apariencia.');
    a.preferences={name:text(p.name,'Nombre',40,true),title:text(p.title,'Nombre del espacio',80),color:p.color,light:p.light,characters:p.characters};
  }else if(b.action==='permissions'){
    if(a.role!=='admin')throw new AppError(403,'Solo el administrador puede cambiar permisos.');
    const target=state.accounts.find(u=>u.id===b.id&&u.role!=='admin');if(!target)throw new AppError(400,'Esta cuenta no puede modificarse.');
    if(!b.permissions||permissionKeys.some(k=>typeof b.permissions[k]!=='boolean'))throw new AppError(400,'Permisos inválidos.');
    target.permissions=Object.fromEntries(permissionKeys.map(k=>[k,b.permissions[k]]));
  }else if(b.action==='logout'){a.authVersion++;}
  else throw new AppError(400,'Acción desconocida.');
  state.revision++;return state;
}
