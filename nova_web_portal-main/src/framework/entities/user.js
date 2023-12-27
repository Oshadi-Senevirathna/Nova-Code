import { Utils } from 'utils/utils';

export const USER_TYPE_SUPER_ADMIN = 'Super Admin';
export const USER_TYPE_MODULE_ADMIN = 'Module Admin';
export const USER_TYPE_OPERATOR = 'Operator';
export const USER_TYPE_CUSTOMER_USER = 'Customer';

class User {
    constructor(object) {
        this.instance_name = object['instance_name'];
        this.UUID = object['UUID'];
        this.email = object['email'];
        this.first_name = object['first_name'];
        this.last_name = object['last_name'];
        this.ad_user = Utils.getBooleanPropertyValue(object, 'ad_user');
        this.ad_admin = Utils.getBooleanPropertyValue(object, 'ad_admin');
        this.ad_sam_account_name = object['ad_sam_account_name'];
        this.ad_user_dn = object['ad_user_dn'];
        this.ad_user_principal_name = object['ad_user_principal_name'];
        this.company = object['company'];
        this.user_type = object['user_type'];
        this.last_login_time = Utils.getNumericPropertyValue(object, 'last_login_time');
        this.login_failure_count = Utils.getNumericPropertyValue(object, 'login_failure_count');
        this.last_login_failure_time = Utils.getNumericPropertyValue(object, 'last_login_failure_time');
        this.password_reset_required = Utils.getBooleanPropertyValue(object, 'password_reset_required');
        this.active = Utils.getBooleanPropertyValue(object, 'active');
        this.created_time = Utils.getNumericPropertyValue(object, 'created_time');
        this.updated_time = Utils.getNumericPropertyValue(object, 'updated_time');
        this.created_by = object['created_by'];
        this.updated_by = object['updated_by'];
        this.roles = object['roles'] || [];
    }

    get rolesString() {
        return this.roles.join(',');
    }
}

export default User;
