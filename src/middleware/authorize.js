const { PrismaClient } = require('@prisma/client');

exports.checkPermission = (permission) =>{
    return async (req , res , next) =>{
        const userId = req.user.id;
        try{
        const hasPermission = await prisma.permission.findFirst({
          where:{
            name: permission,
            roles: {
                some:{
                    role:{
                        users:{
                            some:{
                                userId : userId
                                }   
                            }
                        }
                    }
                }
            }    
        })
        if(!hasPermission){
            return res.status(403).json({ error: 'Forbidden Insufficient Permissions'})
        }
        next();
        }catch(error){
            console.error('Error checking permission:', error);
            return res.status(500).json({ message: 'Internal server error' });
        }
    }
}