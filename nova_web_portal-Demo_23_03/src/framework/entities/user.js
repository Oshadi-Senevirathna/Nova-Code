class User {
    constructor(object) {
        this.instance_name = object['instance_name'];
        this.UUID = object['UUID'];
        this.email = object['email'];
        this.first_name = object['first_name'];
        this.last_name = object['last_name'];
        this.company = object['company'];
        this.roles = object['roles'] || [];
        this.privileges = object['privileges'] || [];
        this.tenants = object['tenants'] || [];
    }
}

export default User;
