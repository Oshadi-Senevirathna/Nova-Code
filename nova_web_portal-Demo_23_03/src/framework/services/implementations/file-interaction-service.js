import config from '../../configs/config.json';
import serviceFactoryInstance from '../service-factory';
import AbstractFileInteractionService from '../abstract/abstract-file-interaction-service';
import axios from '../../../../node_modules/axios/index';

class FileInteractionService extends AbstractFileInteractionService {
    constructor(cache) {
        super();
        this.cache = cache;
        serviceFactoryInstance.authService.getUserObservable().subscribe((user) => {
            if (!user) {
                this.cache.clear();
            }
        });
    }

    async uploadFileToServer(entityName, formData, filename, setProgressFunction, instance) {
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

        return fetch(`${config.nodeURL}/check_upload_file_to_server?entity_name=${entityName}&filename=${filename}`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                if (data.status) {
                    const requestOptionsAxios = {
                        method: 'POST',
                        data: formData,
                        headers: {
                            Authorization: 'Bearer ' + token,
                            Session: sessionID,
                            'Content-Type': 'multipart/form-data'
                        },
                        onUploadProgress: (progressEvent) => {
                            setProgressFunction(Math.round((progressEvent.loaded * 100) / progressEvent.total));
                        }
                    };

                    return axios(
                        `${config.nodeURL}/upload_file_to_server?entity_name=${entityName}&instance=${instance}`,
                        requestOptionsAxios
                    )
                        .then((res) => {
                            var tempInstance = { ...res.data.instance, ...instance };
                            return serviceFactoryInstance.dataLoaderService
                                .addInstance(entityName, tempInstance)
                                .then((data) => {
                                    return data;
                                })
                                .catch((reason) => {
                                    return reason;
                                });
                        })
                        .catch((err) => {
                            this.cache.setNetworkAccessFailedTrue();
                            return err.response.data;
                        });
                } else {
                    return data;
                }
            })
            .catch((reason) => {
                console.log(reason);
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async changeFileName(entityName, instance) {
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
                instance: { ...instance }
            })
        };

        return fetch(`${config.nodeURL}/change_file_name`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                console.log(reason);
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async deleteFile(entityName, UUID) {
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

        return fetch(`${config.nodeURL}/delete_file`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                console.log(reason);
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async downloadFile(entityName, UUID) {
        const requestOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        };

        return fetch(`${config.nodeURL}/download_file?entity_name=${entityName}&UUID=${UUID}`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                console.log(reason);
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }
}

export default FileInteractionService;
