class AbstractAuthService {
    login(username, password) {}

    logout() {}

    changePassword(newPassword) {}

    resetPassword() {}

    isLoggedIn() {}

    hasPrivilege(privilege) {}
}

export default AbstractAuthService;
