let mongoose = require('mongoose');
let { on_db_listen_data_update } = require('../middleware/web_socket.js');
let dbAccess = require('./db_access.js');
let dotenv = require('dotenv');
dotenv.config();

class DBListener {

    constructor(){
        this.temp = "temporary"
        this.listenDBList = ['frontend_jobs','device']
    }

    listenDB(){
        for(let i=0; i<this.listenDBList.length; i++){
            this.listen(this.listenDBList[i])
        }
    }

    listen(entity_name){
        const schema = new mongoose.Schema({}, { strict: false });
        const collection = mongoose.model(entity_name, schema, entity_name);
        collection.watch().on('change', data => collectionChange(data));
        const collectionChange = (data) => {
            if(data.operationType === 'delete'){
                const msg = {
                    notification_type: `${data.operationType}_entity_instance`,
                    payload : {
                        entity_name : entity_name,
                        instances : [data.documentKey]
                    },
                }   
                on_db_listen_data_update(msg)
             
            }else{
                const msg = {
                    notification_type: `${data.operationType}_entity_instance`,
                    payload : {
                        entity_name : entity_name,
                        instances : [data.fullDocument]
                    },
                }
                on_db_listen_data_update(msg)
            
            }
        }
    }
}
//insert


module.exports = new DBListener()
