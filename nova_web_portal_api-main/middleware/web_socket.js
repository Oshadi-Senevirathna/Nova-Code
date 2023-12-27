/* in payload msg, there will be notification types 
["insert_entity_instance", "delete_entity_instance", "replace_entity_instance"]
 */

const on_data_update = (msg) => {
  let wss = require('../index.js');
  let dbListener = require('../db_access/db_listener'); 
  
  var id = -1
  if(msg.payload.entity_name){
    id = (dbListener.listenDBList).findIndex((id) => id === msg.payload.entity_name)
  }

  if(!(id>-1)){
    const broadcastMsg = {
      notification: "update",
      payload: msg
    }
    wss.clients.forEach(function each(client) {
      client.send(JSON.stringify(broadcastMsg));
    });
  }
}

const on_db_listen_data_update = (msg) => {
  let wss = require('../index.js');
  const broadcastMsg = {
        notification: "update",
        payload: msg
      }
  wss.clients.forEach(function each(client) {
    client.send(JSON.stringify(broadcastMsg));
  });
}

module.exports = {on_data_update, on_db_listen_data_update}