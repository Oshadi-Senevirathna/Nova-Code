import { EMPTY } from 'rxjs';
import config from '../../configs/config.json';
import {
    ENTITY_NAME_USERS,
    ENTITY_NAME_SETTINGS,
    ENTITY_NAME_USER_ROLES,
    ENTITY_NAME_USER_PRIVILEGES,
    ENTITY_NAME_DEVICE,
    ENTITY_NAME_FRONTEND_JOBS,
    ENTITY_NAME_TENANT,
    ENTITY_NAME_VM_IMAGE,
    ENTITY_NAME_LOGS_USER,
    ENTITY_NAME_VM_CONFIGS,
    ENTITY_NAME_VM_TEMPLATES,
    ENTITY_NAME_INVENTORY_LOGS,
    ENTITY_NAME_COMPANY
} from '../../caching/entity-cache';
import EntitySubscription from '../../caching/entity-subscription';
import serviceFactoryInstance from '../service-factory';
import AbstractDataLoaderService from '../abstract/abstract-data-loader-service';

const entities = {
    [ENTITY_NAME_TENANT]: {
        name: ENTITY_NAME_TENANT,
        endpoint: `/get_filtered_and_sorted_instances?entity_name=${ENTITY_NAME_TENANT}`
    },
    [`${ENTITY_NAME_TENANT}>summary`]: {
        name: ENTITY_NAME_TENANT,
        endpoint: `/get_filtered_and_sorted_instances_summary?entity_name=${ENTITY_NAME_TENANT}`
    },
    [ENTITY_NAME_COMPANY]: {
        name: ENTITY_NAME_COMPANY,
        endpoint: `/get_filtered_and_sorted_instances?entity_name=${ENTITY_NAME_COMPANY}`
    },
    [`${ENTITY_NAME_COMPANY}>summary`]: {
        name: ENTITY_NAME_COMPANY,
        endpoint: `/get_filtered_and_sorted_instances_summary?entity_name=${ENTITY_NAME_COMPANY}`
    },
    [ENTITY_NAME_LOGS_USER]: {
        name: ENTITY_NAME_LOGS_USER,
        endpoint: `/get_filtered_and_sorted_instances?sort_by=timestamp&sort_direction=-1&entity_name=${ENTITY_NAME_LOGS_USER}`
    },
    [ENTITY_NAME_INVENTORY_LOGS]: {
        name: ENTITY_NAME_INVENTORY_LOGS,
        endpoint: `/get_filtered_and_sorted_instances?sort_by=timestamp&sort_direction=-1&entity_name=${ENTITY_NAME_INVENTORY_LOGS}`
    },
    [ENTITY_NAME_USER_PRIVILEGES]: {
        name: ENTITY_NAME_USER_PRIVILEGES,
        endpoint: `/get_filtered_and_sorted_instances?entity_name=${ENTITY_NAME_USER_PRIVILEGES}`
    },
    [ENTITY_NAME_SETTINGS]: {
        name: ENTITY_NAME_SETTINGS,
        endpoint: `/get_filtered_and_sorted_instances?entity_name=${ENTITY_NAME_SETTINGS}`
    },
    [ENTITY_NAME_DEVICE]: {
        name: ENTITY_NAME_DEVICE,
        endpoint: `/get_filtered_and_sorted_instances?entity_name=${ENTITY_NAME_DEVICE}`
    },
    [`${ENTITY_NAME_DEVICE}>summary`]: {
        name: ENTITY_NAME_DEVICE,
        endpoint: `/get_filtered_and_sorted_instances_summary?entity_name=${ENTITY_NAME_DEVICE}`
    },
    [ENTITY_NAME_VM_CONFIGS]: {
        name: ENTITY_NAME_VM_CONFIGS,
        endpoint: `/get_filtered_and_sorted_instances?entity_name=${ENTITY_NAME_VM_CONFIGS}`
    },
    [ENTITY_NAME_VM_TEMPLATES]: {
        name: ENTITY_NAME_VM_TEMPLATES,
        endpoint: `/get_filtered_and_sorted_instances?entity_name=${ENTITY_NAME_VM_TEMPLATES}`
    },
    [`${ENTITY_NAME_VM_TEMPLATES}>summary`]: {
        name: ENTITY_NAME_VM_TEMPLATES,
        endpoint: `/get_filtered_and_sorted_instances_summary?entity_name=${ENTITY_NAME_VM_TEMPLATES}`
    },
    [ENTITY_NAME_VM_IMAGE]: {
        name: ENTITY_NAME_VM_IMAGE,
        endpoint: `/get_filtered_and_sorted_instances?entity_name=${ENTITY_NAME_VM_IMAGE}`
    },
    [`${ENTITY_NAME_VM_IMAGE}>summary`]: {
        name: ENTITY_NAME_VM_IMAGE,
        endpoint: `/get_filtered_and_sorted_instances_summary?entity_name=${ENTITY_NAME_VM_IMAGE}`
    },
    [ENTITY_NAME_FRONTEND_JOBS]: {
        name: ENTITY_NAME_FRONTEND_JOBS,
        endpoint: `/get_filtered_and_sorted_instances?sort_by=created_at&sort_direction=-1&entity_name=${ENTITY_NAME_FRONTEND_JOBS}`
    },
    [ENTITY_NAME_USERS]: {
        name: ENTITY_NAME_USERS,
        endpoint: `/get_users?entity_name=${ENTITY_NAME_USERS}`
    },
    [ENTITY_NAME_USER_ROLES]: {
        name: ENTITY_NAME_USER_ROLES,
        endpoint: `/get_roles?entity_name=${ENTITY_NAME_USER_ROLES}`
    },
    [`${ENTITY_NAME_DEVICE}>dashboard>device_status`]: {
        name: ENTITY_NAME_DEVICE,
        endpoint: '/dashboard_device_status'
    },
    [`${ENTITY_NAME_DEVICE}>dashboard>device_os`]: {
        name: ENTITY_NAME_DEVICE,
        endpoint: '/dashboard_device_os'
    },
    [`${ENTITY_NAME_FRONTEND_JOBS}>dashboard>job`]: {
        name: ENTITY_NAME_FRONTEND_JOBS,
        endpoint: '/dashboard_job'
    },
    [`${ENTITY_NAME_DEVICE}>dashboard>count_device`]: {
        name: ENTITY_NAME_DEVICE,
        endpoint: `/dashboard_count?entity_name=${ENTITY_NAME_DEVICE}`
    },
    [`${ENTITY_NAME_VM_IMAGE}>dashboard>count_vm_image`]: {
        name: ENTITY_NAME_VM_IMAGE,
        endpoint: `/dashboard_count?entity_name=${ENTITY_NAME_VM_IMAGE}`
    },
    [`${ENTITY_NAME_TENANT}>dashboard>count_tenant`]: {
        name: ENTITY_NAME_TENANT,
        endpoint: `/dashboard_count?entity_name=${ENTITY_NAME_TENANT}`
    },
    [`${ENTITY_NAME_FRONTEND_JOBS}>dashboard>count_frontend_jobs_job_picked`]: {
        name: ENTITY_NAME_FRONTEND_JOBS,
        endpoint: `/dashboard_count?entity_name=${ENTITY_NAME_FRONTEND_JOBS}&findBy=status&value=JOB_PICKED`
    }
};

class DataLoaderService extends AbstractDataLoaderService {
    constructor(cache) {
        super();
        this.cache = cache;
        serviceFactoryInstance.authService.getUserObservable().subscribe((user) => {
            if (!user) {
                this.cache.clear();
            }
        });
    }

    dataSub(entity_name, tenant, noOfInstances, startOfInstances, queryString, fields, sortField, sortDirection, filterField, filterValue) {
        if (entity_name) {
            if (this.cache.mapEntitySubscriptions.get(entity_name) === undefined) {
                if (entities.hasOwnProperty(entity_name)) {
                    const entity = entities[entity_name];
                    const subscription = new EntitySubscription(
                        this,
                        entity,
                        tenant,
                        noOfInstances,
                        startOfInstances,
                        queryString,
                        fields,
                        sortField,
                        sortDirection,
                        filterField,
                        filterValue
                    );
                    this.cache.mapEntitySubscriptions.set(entity_name, subscription);
                    console.log('EntitySubscription added on loadup for the entity: ', entity_name);
                } else {
                    console.log('Subscription is not defined');
                    return EMPTY;
                }
            }
            return this.cache
                .getEntitySubscription(entity_name)
                .getObservable(
                    tenant,
                    noOfInstances,
                    startOfInstances,
                    queryString,
                    fields,
                    sortField,
                    sortDirection,
                    filterField,
                    filterValue
                );
        } else {
            return EMPTY;
        }
    }

    countSub(entity_name) {
        if (entity_name) {
            if (this.cache.mapEntitySubscriptions.get(entity_name) !== undefined) {
                return this.cache.getEntitySubscription(entity_name).getCountObservable();
            }
        } else {
            return EMPTY;
        }
    }

    async getInstance(UUID, entity_name, unshaped) {
        let unshapedTemp;
        if (unshaped === false) {
            unshapedTemp = false;
        } else {
            unshapedTemp = true;
        }

        const endpoint = `/get_instance?entity_name=${entity_name}&UUID=${UUID}&unshaped=${unshapedTemp}`;
        const token = serviceFactoryInstance.authService.getAuthToken();
        const sessionID = serviceFactoryInstance.authService.getSessionID();
        const requestOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + token,
                Session: sessionID
            }
        };

        return fetch(`${config.nodeURL}${endpoint}`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async getFieldValues(entity_name, field) {
        const endpoint = `/get_field_values?entity_name=${entity_name}&field=${field}`;
        console.log(endpoint);
        const token = serviceFactoryInstance.authService.getAuthToken();
        const sessionID = serviceFactoryInstance.authService.getSessionID();
        const requestOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + token,
                Session: sessionID
            }
        };

        return fetch(`${config.nodeURL}${endpoint}`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async getFilteredAndSortedInstances(
        entity_name,
        queryString,
        queryStringFields,
        sort_by,
        sort_direction,
        findBy,
        value,
        direction,
        unshaped
    ) {
        var url = `/get_filtered_and_sorted_instances?entity_name=${entity_name}&unshaped=${unshaped}`;

        if (findBy !== undefined && value !== undefined) {
            url = `${url}&findBy=${findBy}&value=${value}&direction=${direction}`;
        }

        if (queryString && queryString.length !== undefined && queryString.length > 0 && queryStringFields) {
            url = `${url}&queryString=${queryString}&queryStringFields=[${queryStringFields}]`;
        }

        if (sort_by) {
            url = `${url}&sort_direction=${sort_direction}&sort_by=${sort_by}`;
        }

        const token = serviceFactoryInstance.authService.getAuthToken();
        const sessionID = serviceFactoryInstance.authService.getSessionID();
        const requestOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + token,
                Session: sessionID
            }
        };

        return fetch(`${config.nodeURL}${url}`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async addInstance(entityName, instance) {
        const token = serviceFactoryInstance.authService.getAuthToken();
        const sessionID = serviceFactoryInstance.authService.getSessionID();
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + token,
                Session: sessionID
            },
            body: JSON.stringify({
                entity_name: entityName,
                payload: { ...instance }
            })
        };

        return fetch(`${config.nodeURL}/add_instance`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async runjob(UUID) {
        const token = serviceFactoryInstance.authService.getAuthToken();
        const sessionID = serviceFactoryInstance.authService.getSessionID();
        const requestOptions = {
            method: 'OPTIONS',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + token,
                Session: sessionID
            },
            body: JSON.stringify({
                UUID: UUID
            })
        };

        return fetch(`${config.pythonURL}/run_job`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                return reason;
            });
    }

    async applyTemplate(template, devices) {
        const token = serviceFactoryInstance.authService.getAuthToken();
        const sessionID = serviceFactoryInstance.authService.getSessionID();
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + token,
                Session: sessionID
            },
            body: JSON.stringify({
                template: template,
                devices: devices
            })
        };

        return fetch(`${config.pythonURL}/apply_template`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                return reason;
            });
    }

    async deleteInstance(entityName, UUID) {
        const token = serviceFactoryInstance.authService.getAuthToken();
        const sessionID = serviceFactoryInstance.authService.getSessionID();
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + token,
                Session: sessionID
            },
            body: JSON.stringify({
                entity_name: entityName,
                UUID: UUID
            })
        };

        return fetch(`${config.nodeURL}/delete_instance`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async updateInstance(entityName, updatedInstance) {
        delete updatedInstance._id;
        const token = serviceFactoryInstance.authService.getAuthToken();
        const sessionID = serviceFactoryInstance.authService.getSessionID();
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + token,
                Session: sessionID
            },
            body: JSON.stringify({
                entity_name: entityName,
                payload: { ...updatedInstance }
            })
        };

        return fetch(`${config.nodeURL}/update_instance`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async updateInstances(entityName, updatedInstance, UUIDs) {
        const token = serviceFactoryInstance.authService.getAuthToken();
        const sessionID = serviceFactoryInstance.authService.getSessionID();
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + token,
                Session: sessionID
            },
            body: JSON.stringify({
                entity_name: entityName,
                updatedInstance: { ...updatedInstance },
                UUIDs: UUIDs
            })
        };

        return fetch(`${config.nodeURL}/update_instances`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async loadData(entity, cb) {
        const requestOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + serviceFactoryInstance.authService.getAuthToken(),
                Session: serviceFactoryInstance.authService.getSessionID()
            }
        };

        var url = `${config.nodeURL}${entity.endpoint}`;
        if (entity.noOfInstances !== undefined && entity.startOfInstances !== undefined) {
            url = `${url}&noOfInstances=${entity.noOfInstances}&startOfInstances=${entity.startOfInstances}`;
        }

        if (entity.tenant !== undefined && entity.tenant.UUID !== 0 && entity.filterField === undefined) {
            const findBy = '["tenant_id"]';
            const value = `["${entity.tenant.UUID}"]`;
            const direction = '["0"]';
            url = `${url}&findBy=${findBy}&value=${value}&direction=${direction}`;
        }
        if (entity.tenant !== undefined && entity.tenant.UUID !== 0 && entity.filterField !== undefined) {
            const findBy = `["tenant_id","${entity.filterField}"]`;
            const value = `["${entity.tenant.UUID}","${entity.filterValue}"]`;
            const direction = '["0","0"]';
            url = `${url}&findBy=${findBy}&value=${value}&direction=${direction}`;
        }
        if ((entity.tenant === undefined || entity.tenant.UUID === 0) && entity.filterField !== undefined) {
            const findBy = `["${entity.filterField}"]`;
            const value = `["${entity.filterValue}"]`;
            const direction = '["0"]';
            url = `${url}&findBy=${findBy}&value=${value}&direction=${direction}`;
        }

        if (entity.queryString && entity.queryString.length !== undefined && entity.queryString.length > 0 && entity.fields) {
            url = `${url}&queryString=${entity.queryString}&queryStringFields=[${entity.fields}]`;
        }

        if (entity.sortField) {
            url = `${url}&sort_direction=${entity.sortDirection}&sort_by=${entity.sortField}`;
        }

        console.log(url);
        return fetch(url, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                if (data.status) {
                    const instances = data?.instances || [];
                    const count = data?.count || 0;
                    return { instances, count };
                } else {
                    return { instances: [], count: 0 };
                }
            })
            .then((data) => {
                return cb(data);
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return cb([]);
            });
    }
}

export default DataLoaderService;
