import AuthService from './implementations/auth-service';
import DataLoaderService from './implementations/data-loader-service';
import WebSocketService from './implementations/web-socket-service';
import FileInteractionService from './implementations/file-interaction-service';
import EntityCache from '../caching/entity-cache';

export class ServiceFactory {
    cache = new EntityCache(this);
    authService = null;
    dataLoaderService = null;
    fileInteractionService = null;
    webSocketService = null;

    init() {
        this.authService = new AuthService(this.cache);
        this.webSocketService = new WebSocketService(this.cache);
        this.dataLoaderService = new DataLoaderService(this.cache);
        this.fileInteractionService = new FileInteractionService(this.cache);
    }
}

const serviceFactoryInstance = new ServiceFactory();
export default serviceFactoryInstance;
