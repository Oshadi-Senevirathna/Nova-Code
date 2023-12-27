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

    constructor(cache) {
        super();
        this.cache = cache;

        this.sessionID = JSON.parse(localStorage.getItem(AuthService.SESSION_ID));
        this.authToken = JSON.parse(localStorage.getItem(AuthService.AUTH_TOKEN));

        if (this.authToken) {
            this.currentUser = new User(JSON.parse(localStorage.getItem(AuthService.CURRENT_USER)));
            this.privileges = new Set(JSON.parse(localStorage.getItem(AuthService.PRIVILEGES) || '[]'));
            this.roles = new Set(JSON.parse(localStorage.getItem(AuthService.ROLES) || '[]'));
        }

        this.userSubject = new BehaviorSubject(this.currentUser);
        this.tenantSubject = new BehaviorSubject();

        if (this.isLoggedIn()) {
            this.fetchCurrentUserAndPrivileges(this.authToken)
                .then((result) => this.setCurrentUserAndPrivileges(result))
                .catch((reason) => console.error('Failed to fetch current user and privileges on startup', reason));
        }
    }

    getUserObservable() {
        return this.userSubject.asObservable();
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

    isLoggedIn() {
        return this.authToken !== null && this.authToken !== undefined && this.authToken !== '';
    }

    async login(username, password, cb) {
        const requestOptions = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, pwd: password })
        };

        let authToken;
        let sessionID;

        return fetch(`${config.nodeURL}/authenticate`, requestOptions)
            .then((response) => response.json())
            .then((response) => (response.status === false ? Promise.reject(response.reason) : Promise.resolve(response)))
            .then((data) => {
                authToken = data.jwt;
                sessionID = data.session;
                return this.fetchCurrentUserAndPrivileges(authToken);
            })
            .then((result) => {
                this.setCurrentUserAndPrivileges(result);
                this.authToken = authToken;
                this.sessionID = sessionID;
                localStorage.setItem(AuthService.AUTH_TOKEN, JSON.stringify(authToken));
                localStorage.setItem(AuthService.SESSION_ID, JSON.stringify(sessionID));
                this.userSubject.next(this.currentUser);
                console.log(this.authToken);
                return cb(true);
            })
            .catch((reason) => cb(false, reason));
    }

    async logout() {
        console.log('AuthService:logout');
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
        serviceFactoryInstance.webSocketService.closeWS();
        window.location.href = '/';
        await fetch(`${config.nodeURL}/logout`, requestOptions);
        return cb();
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
        console.log(user);
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

    async fetchCurrentUserAndPrivileges(autToken) {
        const requestOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + autToken,
                Session: this.sessionID
            }
        };

        const userPrivileges = await fetch(`${config.nodeURL}/user_privileges`, requestOptions)
            .then((response) => response.json())
            .then((response) => (response.status === false ? Promise.reject(response.reason) : Promise.resolve(response)))
            .then((response) => response.instance);

        const user = new User(userPrivileges.user);
        const privileges = userPrivileges.privileges;
        const roles = userPrivileges.roles;

        return [user, privileges, roles];
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

    async changeCredentials(currentPassword, newPassword) {
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + this.authToken,
                Session: this.sessionID
            },
            body: JSON.stringify({ pwd: currentPassword, new_pwd: newPassword })
        };

        return fetch(`${config.nodeURL}/change_credentials`, requestOptions)
            .then((response) => response.json())
            .then((data) => {
                return data;
            })
            .catch((reason) => {
                this.cache.setNetworkAccessFailedTrue();
                return reason;
            });
    }

    setCurrentUserAndPrivileges(result) {
        this.currentUser = result[0];
        this.privileges = new Set(result[1]);
        this.roles = new Set(result[2]);
        localStorage.setItem(AuthService.CURRENT_USER, JSON.stringify(result[0]));
        localStorage.setItem(AuthService.PRIVILEGES, JSON.stringify(result[1]));
        localStorage.setItem(AuthService.ROLES, JSON.stringify(result[2]));
    }

    setTenant(tenant) {
        console.log(tenant);
        this.tenantSubject.next(tenant);
    }

    hasPrivilegeUpdateGeneralSettings() {
        return this.hasPrivilege(UPDATE_GENERAL_SETTINGS);
    }

    hasPrivilegeUpdateApplicationSettings() {
        return this.hasPrivilege(UPDATE_APPLICATION_SETTINGS);
    }

    hasPrivilegeViewDevices() {
        return this.hasPrivilege(VIEW_DEVICES) || this.hasPrivilege(MANAGE_DEVICES);
    }
    hasPrivilegeManageDevices() {
        return this.hasPrivilege(MANAGE_DEVICES);
    }

    hasPrivilegeManageDiscovery() {
        return this.hasPrivilege(MANAGE_DISCOVERY);
    }

    hasPrivilegeManageUsers() {
        return this.hasPrivilege(MANAGE_USERS);
    }

    hasPrivilegeManageProvisioning() {
        return this.hasPrivilege(MANAGE_PROVISIONING);
    }

    hasPrivilegeViewWorkorder() {
        return this.hasPrivilege(VIEW_WORKORDER) || this.hasPrivilege(MANAGE_WORKORDER);
    }
    hasPrivilegeManageWorkorder() {
        return this.hasPrivilege(MANAGE_WORKORDER);
    }

    hasPrivilegeViewLogs() {
        return this.hasPrivilege(VIEW_LOGS);
    }

    hasPrivilegeViewDashboard() {
        return this.hasPrivilege(VIEW_DASHBOARD);
    }

    hasPrivilegeViewHealth() {
        return this.hasPrivilege(VIEW_HEALTH);
    }

    hasPrivilege(privilege) {
        if (this.privileges === undefined) {
            return false;
        }
        if (privilege !== undefined) {
            return this.privileges.has(privilege);
        }
        return true;
    }

    hasPrivilegeEditAppAdminRole() {
        return this.hasRole(SUPER_ADMIN_ROLE);
    }

    hasPrivilegeEditUserRole() {
        return this.hasRole(APP_ADMIN_ROLE) || this.hasRole(SUPER_ADMIN_ROLE);
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
