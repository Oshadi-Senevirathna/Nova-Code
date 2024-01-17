class AbstractAuthService {
    login(username, password) {}

    logout() {}

    changePassword(newPassword) {}

    resetPassword() {}

    hasPrivilege(privilege) {}
}

export default AbstractAuthService;
