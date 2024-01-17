import config from '../../configs/config.json';
import serviceFactoryInstance from '../service-factory';
import AbstractWebSocketService from '../abstract/abstract-web-socket-service';

class WebSocketService extends AbstractWebSocketService {
    constructor(cache) {
        super();
        this.cache = cache;

        serviceFactoryInstance.authService.getUserObservable().subscribe((user) => {
            console.log(user);
            if (user) {
                this.ws = new WebSocket(`${config.wsUrl}?token=${serviceFactoryInstance.authService.getAuthToken()}`);
                this.connectWS();
            }
        });

        this.NO_OF_ATTEMPTS = 3;
    }

    async load() {
        // We need to wrap the loop into an async function for this to work
        const timer = (ms) => new Promise((res) => setTimeout(res, ms));
        for (var i = 0; i < 3; i++) {
            console.log(i);
            this.connectWS();
            await timer(15000); // then the created Promise can be awaited
        }
        console.log('websocket logout');
        serviceFactoryInstance.authService.logout();
    }

    connectWS() {
        console.log('connecting');
        this.ws.onopen = () => console.log('Websocket opened');
        this.ws.onclose = () => {
            console.log('Websocket closed. Attempting re-connect');
            this.load();
        };

        this.ws.onmessage = async (evt) => {
            const jsonMsg = JSON.parse(evt.data);
            console.log('Websocket update received: ', jsonMsg.payload);
            if (jsonMsg.notification === 'update') {
                this.cache.onNotification(jsonMsg.payload);
            }
        };
    }

    closeWS() {
        console.log('Websocket closed on logout');
        this.ws.close();
    }
}

export default WebSocketService;
