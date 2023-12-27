async function verify_session_user_privilege(session_id, auth_id, entity_name, action){
    let { get_user_from_jwt_token } = require('./auth.js');
    let check_privilege = require('./check_privilege.js');
    let { userSessionUpdate } = require('./user_session.js');

    const validSession = userSessionUpdate(session_id)
    if (!validSession)
    return ({ 
      status:false,
      errorCode:400,
      reason: "Session is terminated" });

    const current_user=get_user_from_jwt_token(auth_id)
    if (!current_user)
    return ({ 
        status:false,
        errorCode:400,
        reason: "Invalid authorization token" });

    /* const check = check_privilege(current_user, entity_name, action)
    if (!check)
        return ({ 
        status:false,
        errorCode:403,
        reason: "Encountered an error when accessing the database" }); */

    return ({status: true,
    current_user:current_user
    })
}


module.exports = verify_session_user_privilege