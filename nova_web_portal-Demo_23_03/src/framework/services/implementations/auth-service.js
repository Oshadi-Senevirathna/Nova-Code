import { BehaviorSubject } from 'rxjs';
import config from '../../configs/config.json';
import {
    APP_ADMIN_ROLE,
    MANAGE_DEVICES,
    MANAGE_DISCOVERY,
    MANAGE_PROVISIONING,
    MANAGE_USERS,
    MANAGE_WORKORDER,
    SUPER_ADMIN_ROLE,
    UPDATE_APPLICATION_SETTINGS,
    UPDATE_GENERAL_SETTINGS,
    VIEW_DASHBOARD,
    VIEW_DEVICES,
    VIEW_HEALTH,
    VIEW_LOGS,
    VIEW_WORKORDER
} from '../../entities/role';
import User from '../../entities/user';
import AbstractAuthService from '../abstract/abstract-auth-service';
import serviceFactoryInstance from '../service-factory';

class AuthService extends AbstractAuthService {
    static get AUTH_TOKEN() {
        return 'authToken';
    }

    static get SESSION_ID() {
        return 'session_id';
    }

    static get CURRENT_USER() {
        return 'currentUser';
    }

    static get PRIVILEGES() {
        return 'privileges';
    }

    static get ROLES() {
        return 'roles';
    }

    static get TENANT() {
        return 'tenant';
    }

    static get TENANTS() {
        return 'tenants';
    }

    static get ALLTENANTTENANT() {
        var allTenant = {};
        allTenant.instance_name = 'All';
        allTenant.UUID = 0;
        return allTenant;
    }

    constructor(cache) {
        super();
        this.cache = cache;
        this.sessionID = null;
        this.authToken = null;
        this.currentUser = null;
        this.allTenants = null;

        this.userSubject = new BehaviorSubject();
        this.allTenantsSubject = new BehaviorSubject();
        this.tenantSubject = new BehaviorSubject();

        this.allTenantsSubject.next([AuthService.ALLTENANTTENANT]);
        this.tenantSubject.next(AuthService.ALLTENANTTENANT);

        if (localStorage.getItem(AuthService.SESSION_ID) !== null && localStorage.getItem(AuthService.AUTH_TOKEN) !== null) {
            if (!this.sessionID && !this.authToken) {
                this.sessionID = localStorage.getItem(AuthService.SESSION_ID);
                this.authToken = localStorage.getItem(AuthService.AUTH_TOKEN);
            }
        } else {
            this.logout();
        }

        if (localStorage.getItem(AuthService.CURRENT_USER)) {
            this.currentUser = JSON.parse(localStorage.getItem(AuthService.CURRENT_USER));
            this.userSubject.next(this.currentUser);
        }
        if (localStorage.getItem(AuthService.TENANTS)) {
            this.allTenants = JSON.parse(localStorage.getItem(AuthService.TENANTS));
            this.allTenantsSubject.next(this.allTenants);
        }
    }

    getUserObservable() {
        return this.userSubject.asObservable();
    }

    getAllTenantsObservable() {
        return this.allTenantsSubject.asObservable();
    }

    getTenantObservable() {
        return this.tenantSubject.asObservable();
    }

    getAuthToken() {
        return this.authToken;
    }

    getSessionID() {
        return this.sessionID;
    }

    async login(email, password, cb) {
        console.log('Login user');
        const requestOptions = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, pwd: password })
        };

        return fetch(`${config.nodeURL}/authenticate`, requestOptions)
            .then((response) => response.json())
            .then((response) => (response.status === false ? Promise.reject(response.reason) : Promise.resolve(response)))
            .then((data) => {
                localStorage.setItem(AuthService.TENANTS, JSON.stringify([...data.payload.tenants, AuthService.ALLTENANTTENANT]));
                localStorage.setItem(AuthService.AUTH_TOKEN, data.jwt);
                localStorage.setItem(AuthService.SESSION_ID, data.session);
                var tempUser = data.payload;
                tempUser.tenants.push(AuthService.ALLTENANTTENANT);
                localStorage.setItem(AuthService.CURRENT_USER, JSON.stringify(new User(tempUser)));
            })
            .then(() => {
                this.sessionID = localStorage.getItem(AuthService.SESSION_ID);
                this.authToken = localStorage.getItem(AuthService.AUTH_TOKEN);
                this.allTenants = JSON.parse(localStorage.getItem(AuthService.TENANTS));
                this.allTenantsSubject.next(this.allTenants);
                this.currentUser = JSON.parse(localStorage.getItem(AuthService.CURRENT_USER));
                this.userSubject.next(this.currentUser);
                return cb(true);
            })
            .catch((reason) => cb(false, reason));
    }

    async verifyUser() {
        console.log('Verify user');
        const requestOptions = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + this.authToken, Session: this.sessionID }
        };

        return fetch(`${config.nodeURL}/verify_user`, requestOptions)
            .then((response) => response.json())
            .then((response) => (response.status === false ? Promise.reject(response.reason) : Promise.resolve(response)))
            .then((data) => {
                localStorage.setItem(AuthService.ALLTENANTTENANT, JSON.stringify([...data.payload.tenants, AuthService.ALLTENANTTENANT]));
                localStorage.setItem(AuthService.AUTH_TOKEN, data.jwt);
                localStorage.setItem(AuthService.SESSION_ID, data.session);
                var tempUser = data.payload;
                tempUser.tenants.push(AuthService.ALLTENANTTENANT);
                localStorage.setItem(AuthService.CURRENT_USER, JSON.stringify(new User(tempUser)));
                console.log(data);
            })
            .then(() => {
                this.sessionID = localStorage.getItem(AuthService.SESSION_ID);
                this.authToken = localStorage.getItem(AuthService.AUTH_TOKEN);
                this.allTenants = JSON.parse(localStorage.getItem(AuthService.TENANTS));
                this.allTenantsSubject.next(this.allTenants);
                this.currentUser = JSON.parse(localStorage.getItem(AuthService.CURRENT_USER));
                this.userSubject.next(this.currentUser);

                return cb(true);
            })
            .catch((reason) => console.log('verify fail'));
    }

    async logout() {
        if (this.authToken && this.sessionID) {
            console.log('AuthService:logout 1');
            const requestOptions = {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: 'Bearer ' + this.authToken
                },
                body: JSON.stringify({ session: this.sessionID })
            };

            localStorage.clear();
            this.currentUser = undefined;
            this.authToken = undefined;
            this.privileges = undefined;
            this.roles = undefined;
            this.sessionID = undefined;
            this.userSubject.next(this.currentUser);
            try {
                serviceFactoryInstance.webSocketService.closeWS();
                return fetch(`${config.nodeURL}/logout`, requestOptions)
                    .then(() => {
                        window.location.href = '/';
                    })
                    .catch(() => {
                        window.location.href = '/';
                    });
            } catch {
                console.log('error');
            }
        } else {
            console.log('AuthService:logout 2');
            localStorage.clear();
            this.currentUser = undefined;
            this.authToken = undefined;
            this.privileges = undefined;
            this.roles = undefined;
            this.sessionID = undefined;
            this.userSubject.next(this.currentUser);
            //window.location.href = '/';
            //serviceFactoryInstance.webSocketService.closeWS();
            //window.location.href = '/';
        }
    }

    async addUser(user) {
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + this.authToken,
                Session: this.sessionID
            },
            body: JSON.stringify(user)
        };

        return fetch(`${config.nodeURL}/create_user`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async updateUser(user) {
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + this.authToken,
                Session: this.sessionID
            },
            body: JSON.stringify(user)
        };

        return fetch(`${config.nodeURL}/update_user`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    async resetPassword(password, code, cb) {
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                pwd: password,
                code: code
            })
        };
        return fetch(`${config.nodeURL}/reset_password`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return cb(data);
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return cb(reason);
            });
    }

    async forgotPassword(username) {
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username: username })
        };

        return fetch(`${config.nodeURL}/forgot_password`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    setTenant(tenant) {
        this.tenantSubject.next(tenant);
    }

    hasPrivilege(privilege) {
        for (let i = 0; i < this.currentUser.privileges.length; i++) {
            if (this.currentUser.privileges[i].instance_name === privilege) {
                return true;
            }
        }
        return false;
    }

    hasRole(role) {
        if (this.roles === undefined) {
            return false;
        }
        if (role !== undefined) {
            return this.roles.has(role);
        }
        return true;
    }
}

export default AuthService;
