const SUPABASE_URL=Deno.env.get('SUPABASE_URL')!;
const SECRET=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const origin='https://srmgrandlakes.org';
const cors={'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Headers':'content-type, apikey, authorization','Access-Control-Allow-Methods':'POST, OPTIONS','Vary':'Origin'};
const notificationTo='info@srmgrandlakes.org';
async function notify(subject:string,body:string){
 const apiKey=Deno.env.get('RESEND_API_KEY');
 const from=Deno.env.get('SRM_NOTIFY_FROM');
 if(!apiKey||!from){console.warn('SRM notification email not configured');return}
 try{const response=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+apiKey,'Content-Type':'application/json'},body:JSON.stringify({from,to:[notificationTo],subject,text:body})});
 if(!response.ok)console.error('SRM notification delivery failed',response.status);
 }catch(e){console.error('SRM notification transport unavailable')}
}
const files=['SRM_Great_Lakes_DRC_Security_Risk_Intelligence_2026.pdf','SRM_Great_Lakes_DRC_Security_Risk_Intelligence_2026.pptx','SRM_Great_Lakes_LIBERIA_Security_Risk_Intelligence_2026.pdf','SRM_Great_Lakes_LIBERIA_Security_Risk_Intelligence_2026.pptx','SRM_Great_Lakes_NIGERIA_Security_Risk_Intelligence_2026.pdf','SRM_Great_Lakes_NIGERIA_Security_Risk_Intelligence_2026.pptx'];
const headers={'apikey':SECRET,'Authorization':'Bearer '+SECRET,'Content-Type':'application/json'};
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{...cors,'Content-Type':'application/json','Cache-Control':'no-store'}});
const hash=async(s:string)=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(b=>b.toString(16).padStart(2,'0')).join('');
async function rows(query:string){const r=await fetch(SUPABASE_URL+'/rest/v1/library_access_passes?'+query,{headers});if(!r.ok)throw Error('Database unavailable');return await r.json()}
Deno.serve(async req=>{
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers:cors});
 if(req.method!=='POST')return json({error:'Method not allowed'},405);
 const reqOrigin=req.headers.get('origin');if(reqOrigin&&reqOrigin!==origin)return json({error:'Origin not permitted'},403);
 let data:any;try{data=await req.json()}catch{return json({error:'Invalid request'},400)}
 if(data?.action==='register'){
  const name=String(data.name||'').trim(),email=String(data.email||'').trim().toLowerCase(),organization=String(data.organization||'').trim();
  if(name.length<2||name.length>150||organization.length>200||email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||data.consent!==true||data.website)return json({error:'Check your name, email and consent.'},400);
  const ip=req.headers.get('cf-connecting-ip')||req.headers.get('x-real-ip')||req.headers.get('x-forwarded-for')?.split(',')[0]||'unknown';
  const ipHash=await hash(ip);
  const since=new Date(Date.now()-3600000).toISOString();
  try{
   const recentIp=await rows('select=id&ip_hash=eq.'+ipHash+'&created_at=gte.'+encodeURIComponent(since)+'&limit=6');
   const recentEmail=await rows('select=id&email=eq.'+encodeURIComponent(email)+'&created_at=gte.'+encodeURIComponent(since)+'&limit=4');
   if(recentIp.length>5||recentEmail.length>3)return json({error:'Too many registrations. Please try again later.'},429);
   const raw=Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b=>b.toString(16).padStart(2,'0')).join('');
   const tokenHash=await hash(raw);
   const res=await fetch(SUPABASE_URL+'/rest/v1/library_access_passes',{method:'POST',headers:{...headers,'Prefer':'return=minimal'},body:JSON.stringify({full_name:name,organization:organization||null,email,consent_version:'2026-11-23',token_hash:tokenHash,ip_hash:ipHash})});
   if(!res.ok)return json({error:'Registration unavailable. Please try later.'},503);
   await notify('SRM Great Lakes: New library registration','New registration\nName: '+name+'\nEmail (unverified): '+email+'\nOrganization: '+(organization||'Not provided')+'\nTime: '+new Date().toISOString());
   return json({token:raw,expires_in_days:30,notice:'Email address is not verified. Keep this browser to retain access.'});
  }catch{return json({error:'Registration service temporarily unavailable.'},503)}
 }
 if(data?.action==='download'){
  const token=String(data.token||''),file=String(data.file||'');
  if(!/^[a-f0-9]{64}$/.test(token)||!files.includes(file))return json({error:'Access denied'},403);
  try{
   const found=await rows('select=id,full_name,email,organization&token_hash=eq.'+await hash(token)+'&expires_at=gt.'+encodeURIComponent(new Date().toISOString())+'&limit=1');
   if(found.length!==1)return json({error:'Access expired or invalid. Please register again.'},403);
   const r=await fetch(SUPABASE_URL+'/storage/v1/object/authenticated/intelligence-reports/'+encodeURIComponent(file),{headers});
   if(!r.ok)return json({error:'Report unavailable'},502);
   const event=await fetch(SUPABASE_URL+'/rest/v1/library_download_events',{method:'POST',headers:{...headers,'Prefer':'return=minimal'},body:JSON.stringify({access_pass_id:found[0].id,file_name:file})});
   if(!event.ok)console.error('SRM download audit insert failed',event.status);
   await notify('SRM Great Lakes: Report downloaded','Report download started\nName: '+found[0].full_name+'\nEmail (unverified): '+found[0].email+'\nOrganization: '+(found[0].organization||'Not provided')+'\nFile: '+file+'\nTime: '+new Date().toISOString());
   return new Response(r.body,{status:200,headers:{...cors,'Content-Type':file.endsWith('.pdf')?'application/pdf':'application/vnd.openxmlformats-officedocument.presentationml.presentation','Content-Disposition':'attachment; filename="'+file+'"','Cache-Control':'no-store'}});
  }catch{return json({error:'Download temporarily unavailable'},503)}
 }
 return json({error:'Unknown action'},400);
});
