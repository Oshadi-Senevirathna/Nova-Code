async function check_privilege (userName, entityName, action) { 
    let dbAccess = require('../db_access/db_access.js');
    const getPrivilege = (entity_name,action) =>{
        switch(entity_name){
            
            case "users":
            case "companies":
            case "roles":{
                if(action==="View"){
                    return "Manage Users"
                }
                else if(action==="Edit"){
                    return "Manage Users"
                }
            }
            break
    
            case "logs_backend":
            case "logs_application":
            case "logs_user": {
                if(action==="View"){
                    return "View Logs"
                }
            }
            break
    
            case "discovery":{
                if(action==="View"){
                    return "Manage Discovery"
                }
                else if(action==="Edit"){
                    return "Manage Discovery"
                }
            }
            break
    
            case "settings":
            case "nw_modeling_parameters":
            case "nw_modeling_properties":
            {
                if(action==="View"){
                    return "Update General Settings"
                }
                else if(action==="Edit"){
                    return "Update General Settings"
                }
            }
            break
    
            case "device_credential":
            case "device_connection_protocol":
            case "device_os":
            case "device_snmp":
            case "device_location":
            case "device_connection_method":
            case "device_category":
            case "device_adaptor":
            case "cron":
            {
                if(action === "View"){
                    return "View Devices"
                }
                else if(action==="Edit"){
                    return "Update Application Settings"
                }
            }
            break
    
            case "device":
            {
                if(action==="View"){
                    return "View Devices"
                }
                else if(action==="Edit"){
                    return "Manage Devices"
                }
            }
            break
    
            case "interface":
            {
                if(action==="View"){
                    return "View Devices"
                }
            }
            break
            
            case "workorder":
            {
                if(action==="View"){
                    return "View Work Order"
                }
                else if(action==="Edit"){
                    return "Manage Work Order"
                }
            }
            break
    
            case "Discovery": 
            {
                return "Manage Discovery"
            }
            break
    
            default:
                return "";
    
        }
    }
    
    try{

        const neededPrivilege = getPrivilege(entityName,action)
        const data = await dbAccess.getInstance('users', 'instance_name', userName, true)
        const user = data.instance
        if(!user){
            return res.status(400).json({ 
              status:false,
              reason: "Invalid credentials" });
          }
        
        const userRoles = user.roles
        var checked = false
        userRoles.forEach(role => {
            const privileges = dbAccess.roles.get(role)
            if(privileges!==undefined){
                privileges.forEach(privilege=>{
                    if(neededPrivilege && neededPrivilege===privilege){
                        checked = true
                    }else if (neededPrivilege===''){
                        checked = true
                    }
                })
            }
        });

        return checked
    
    }catch{
        return false
    }
}

module.exports = check_privilege