async function cleanDelete (referencedEntity, instances, deletedEntities) {
    let dbAccess = require('../db_access/db_access.js');
    
    try{
        
        for (let j=0 ; j<instances.length; j++){
            var temp = {}
            temp[referencedEntity.foreign_field] = instances[j].UUID
            
            const data = await dbAccess.getFilteredAndSortedCollection(referencedEntity.entity_name, [referencedEntity.foreign_field], [instances[j].UUID], [0], true)
            if(data.instances.length>0){   
                if(referencedEntity.action==='delete'){
                    const result = await dbAccess.deleteInstances(referencedEntity.entity_name, referencedEntity.foreign_field, temp, deletedEntities)
                    return result            
                }else if(referencedEntity.action==='setnull'){
                    for(let i=0 ; i<data.instances.length ; i++){
                        var temp = data.instances[i]
                        temp[referencedEntity.foreign_field] = null
                        const result = await dbAccess.replaceInstance(referencedEntity.entity_name, 'UUID', temp['UUID'], temp)
                        if (result.status!==true){
                            return { status: false, reason:"Set null failed"}
                        }
                    }
                    return { status: true, reason:"Set null complete"}
                }else if(referencedEntity.action==='protect'){
                    return { status: false, reason:"Was not able to delete, protected"}
                }
            }else{
                return { status: true, reason:"No dependencies"}
            }
        }
    }catch{
        return { status: false, reason:"Error when trying to delete"}
    }
}

module.exports = cleanDelete