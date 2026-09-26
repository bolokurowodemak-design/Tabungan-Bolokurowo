export default async function handler(req,res){
  if(req.method!=='POST') return res.status(405).json({error:'Method not allowed'});
  try{
    const auth=req.headers.authorization||'';
    const token=auth.replace(/^Bearer\s+/i,'');
    if(!token) return res.status(401).json({error:'Unauthorized'});

    const base=process.env.SUPABASE_URL;
    const key=process.env.SUPABASE_SERVICE_ROLE_KEY;

    if(!base||!key) return res.status(500).json({error:'Server Supabase environment belum diatur'});

    const me=await fetch(base+'/auth/v1/user',{
      headers:{apikey:key,Authorization:'Bearer '+token}
    });

    if(!me.ok) return res.status(401).json({error:'Sesi tidak valid'});

    const authUser=await me.json();

    const prof=await fetch(
      base+'/rest/v1/profiles?id=eq.'+
      encodeURIComponent(authUser.id)+
      '&select=role',
      {
        headers:{
          apikey:key,
          Authorization:'Bearer '+key
        }
      }
    );

    const profiles=await prof.json();

    if(!prof.ok||profiles[0]?.role!=='admin')
      return res.status(403).json({
        error:'Hanya admin yang dapat mengelola anggota'
      });

    const b=req.body||{};

    if(!b.name||!b.username)
      return res.status(400).json({
        error:'Nama dan username wajib diisi'
      });

    let userId=b.userId;

    const email=
      String(b.username)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._-]/g,'_')+
      '@bolokurowo.local';

    const headers={
      apikey:key,
      Authorization:'Bearer '+key,
      'Content-Type':'application/json'
    };

    if(!userId){
      if(!b.password||String(b.password).length<6)
        return res.status(400).json({
          error:'Password minimal 6 karakter'
        });

      const cr=await fetch(
        base+'/auth/v1/admin/users',
        {
          method:'POST',
          headers,
          body:JSON.stringify({
            email,
            password:b.password,
            email_confirm:true,
            user_metadata:{
              username:b.username,
              name:b.name
            }
          })
        }
      );

      const cj=await cr.json();

      if(!cr.ok)
        return res.status(cr.status).json({
          error:cj.msg||cj.message||'Gagal membuat akun login'
        });

      userId=cj.id;

    }else if(b.password){

      const ur=await fetch(
        base+'/auth/v1/admin/users/'+
        encodeURIComponent(userId),
        {
          method:'PUT',
          headers,
          body:JSON.stringify({
            password:b.password,
            email
          })
        }
      );

      const uj=await ur.json();

      if(!ur.ok)
        return res.status(ur.status).json({
          error:uj.msg||uj.message||'Gagal memperbarui akun login'
        });
    }

    const pp=await fetch(
      base+'/rest/v1/profiles?id=eq.'+
      encodeURIComponent(userId),
      {
        method:'PATCH',
        headers,
        body:JSON.stringify({
          username:String(b.username).trim(),
          role:'member'
        })
      }
    );

    if(!pp.ok){
      const pj=await pp.json();

      return res.status(pp.status).json({
        error:pj.message||'Gagal memperbarui profil'
      });
    }

    const payload={
      user_id:userId,
      name:b.name,
      phone:b.phone||'',
      active:b.active!==false
    };

    let mr;

    if(b.memberId){
      mr=await fetch(
        base+'/rest/v1/members?id='+
        encodeURIComponent(b.memberId),
        {
          method:'PATCH',
          headers,
          body:JSON.stringify(payload)
        }
      );
    }else{
      mr=await fetch(
        base+'/rest/v1/members',
        {
          method:'POST',
          headers,
          body:JSON.stringify(payload)
        }
      );
    }

    const mj=mr.ok?{}:await
    mr.json().catch(()=>({}));

    if(!mr.ok)
      return res.status(mr.status).json({
        error:mj.message||'Gagal menyimpan data anggota'
      });

    return res.status(200).json({
      ok:true,
      userId
    });

  }catch(e){
    console.error(e);

    return res.status(500).json({
      error:e.message||'Server error'
    });
  }
            }
