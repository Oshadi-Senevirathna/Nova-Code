
const instanceDetails = (payload, user, action) => {
    const date = Date.now()

    if (action === 'add' && user){
        payload['created_by'] = user
        payload['last_modified_by'] = user
        payload['created_at'] = date
        payload['last_modified_at'] = date
    }
    else if (action === 'edit' && user){
        payload['last_modified_by'] = user
        payload['last_modified_at'] = date
    }

    return payload
}

module.exports = instanceDetails