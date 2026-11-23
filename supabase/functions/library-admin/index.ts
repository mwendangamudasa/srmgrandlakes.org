const url=Deno.env.get('SUPABASE_URL')!,secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const cors={'Access-Control-Allow-Origin':'https://srmgrandlakes.org','Access-Control-Allow-Headers':'authorization,content-type,apikey','Access-Control-Allow-Methods':'POST,OPTIONS','Cache-Control':'no-store','Vary':'Origin'};
const reply=(obj:unknown,status=200)=>new Response(JSON.stringify(obj),{status,headers:{...cors,'Content-Type':'application/json'}});
Deno.serve(async req=>{
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers:cors});
 if(req.method!=='POST')return reply({error:'Method not allowed'},405);
 if(req.headers.get('origin')!=='https://srmgrandlakes.org')return reply({error:'Forbidden origin'},403);
 const token=req.headers.get('authorization')?.replace(/^Bearer\s+/i,'')||'';
 if(!token)return reply({error:'Sign in required'},401);
 try{
  const userRes=await fetch(url+'/auth/v1/user',{headers:{'apikey':secret,'Authorization':'Bearer '+token}});
  if(!userRes.ok)return reply({error:'Invalid session'},401);
  const user=await userRes.json();
  if(user.email?.toLowerCase()!=='info@srmgrandlakes.org'||!user.email_confirmed_at)return reply({error:'Administrator access only'},403);
  const h={'apikey':secret,'Authorization':'Bearer '+secret};
  const read=async(path:string)=>{const r=await fetch(url+'/rest/v1/'+path,{headers:h});if(!r.ok)throw Error('Data retrieval failed');return r.json()};
  const [people,downloads]=await Promise.all([
   read('library_access_passes?select=id,full_name,email,organization,created_at&order=created_at.desc&limit=1000'),
   read('library_download_events?select=id,access_pass_id,file_name,downloaded_at&order=downloaded_at.desc&limit=1000')
  ]);
  return reply({registrations:people,downloads,limited_to_latest:1000,generated_at:new Date().toISOString()});
 }catch{return reply({error:'Dashboard temporarily unavailable'},503)}
});
