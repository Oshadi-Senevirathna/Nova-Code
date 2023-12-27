import { BehaviorSubject } from 'rxjs';

export const ENTITY_NAME_USERS = 'users';
export const ENTITY_NAME_USER_ROLES = 'user_roles';
export const ENTITY_NAME_USER_PRIVILEGES = 'user_privileges';
export const ENTITY_NAME_SETTINGS = 'settings';
export const ENTITY_NAME_DEVICE = 'device';
export const ENTITY_NAME_FRONTEND_JOBS = 'frontend_jobs';
export const ENTITY_NAME_TENANT = 'tenant';
export const ENTITY_NAME_VM_IMAGE = 'vm_image';
export const ENTITY_NAME_LOGS_USER = 'logs_user';
export const ENTITY_NAME_VM_TEMPLATES = 'vm_templates';
export const ENTITY_NAME_VM_CONFIGS = 'vm_configs';
export const ENTITY_NAME_INVENTORY_LOGS = 'inventory_logs';
export const ENTITY_NAME_COMPANY = 'company';

class EntityCache {
    constructor() {
        this.mapEntitySubscriptions = new Map();
        this.networkAccessFailed = new BehaviorSubject();
        this.networkAccessFailed.next(false);
    }

    onNotification(msg) {
        if (msg) {
            if (
                msg.notification_type === 'insert_entity_instance' ||
                msg.notification_type === 'replace_entity_instance' ||
                msg.notification_type === 'delete_entity_instance'
            ) {
                for (const entityName of this.mapEntitySubscriptions.keys()) {
                    const collectionNameTotal = entityName;
                    if (collectionNameTotal === msg.payload?.entity_name && msg.notification_type === 'insert_entity_instance') {
                        const subscription = this.mapEntitySubscriptions.get(entityName);
                        if (subscription) {
                            subscription.add(msg.payload.instances);
                        }
                    } else if (collectionNameTotal === msg.payload?.entity_name && msg.notification_type === 'delete_entity_instance') {
                        const subscription = this.mapEntitySubscriptions.get(entityName);
                        if (subscription) {
                            subscription.delete(msg.payload.instances);
                        }
                    } else if (collectionNameTotal === msg.payload?.entity_name && msg.notification_type === 'replace_entity_instance') {
                        const subscription = this.mapEntitySubscriptions.get(entityName);
                        if (subscription) {
                            subscription.update(msg.payload.instances);
                        }
                    } else {
                        const collectionName = entityName.split('>')[0];
                        if (collectionName === msg.payload?.entity_name) {
                            const subscription = this.mapEntitySubscriptions.get(entityName);
                            if (subscription) {
                                subscription.load();
                            } else {
                                console.error('Error loading entity subscription for entity: ', collectionName);
                            }
                        }
                    }
                }
            }
        }
    }

    clear() {
        console.log('EntityCache:clear');
        this.mapEntitySubscriptions.forEach((subscription) => subscription.close());
        this.mapEntitySubscriptions.clear();
    }

    removeEntitySubscription(entityName) {
        console.log('EntityCache:removeEntitySubscription: ', entityName);
        this.mapEntitySubscriptions.remove(entityName);
    }

    getEntitySubscription(entityName) {
        console.log('EntityCache:getEntitySubscription: ', entityName);
        if (this.mapEntitySubscriptions.has(entityName)) {
            return this.mapEntitySubscriptions.get(entityName);
        }
    }

    setNetworkAccessFailedTrue() {
        this.networkAccessFailed.next(true);
    }

    setNetworkAccessFailedFalse() {
        this.networkAccessFailed.next(false);
    }
}

export default EntityCache;
