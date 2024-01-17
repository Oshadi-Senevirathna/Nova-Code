export const UPDATE_GENERAL_SETTINGS = 'Update General Settings';
export const UPDATE_APPLICATION_SETTINGS = 'Update Application Settings';
export const VIEW_DEVICES = 'View Devices';
export const MANAGE_DEVICES = 'Manage Devices';
export const MANAGE_DISCOVERY = 'Manage Discovery';
export const MANAGE_USERS = 'Manage Users';
export const MANAGE_PROVISIONING = 'Manage Provisioning';
export const VIEW_WORKORDER = 'View Work Order';
export const MANAGE_WORKORDER = 'Manage Work Order';
export const VIEW_LOGS = 'View Logs';
export const VIEW_DASHBOARD = 'View Dashboard';
export const VIEW_HEALTH = 'View Health';
export const SUPER_ADMIN_ROLE = 'Super Administrator';
export const APP_ADMIN_ROLE = 'Application Administrator';

class Role {
    constructor(object) {
        this.instance_name = object['instance_name'];
        this.UUID = object['UUID'];
        this.module = object['module'];
        this.privileges = object['privileges'] || [];
    }
}

export default Role;
