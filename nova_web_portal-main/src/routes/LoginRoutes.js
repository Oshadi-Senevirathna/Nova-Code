import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MinimalLayout from 'layout/MinimalLayout';

// render - login
const AuthLogin = Loadable(lazy(() => import('pages/authentication/Login')));
const AuthForgotPassword = Loadable(lazy(() => import('pages/authentication/ForgotPassword')));
const AuthResetPassword = Loadable(lazy(() => import('pages/authentication/ResetPassword')));

// ==============================|| AUTH ROUTING ||============================== //

const LoginRoutes = {
    path: '/',
    element: <MinimalLayout />,
    children: [
        {
            path: '/',
            element: <AuthLogin title={'Nova | Login'} />
        },
        {
            path: '/forgot-password',
            element: <AuthForgotPassword title={'Nova | Forgot password'} />
        },
        {
            path: '/reset-password',
            element: <AuthResetPassword title={'Nova | Reset password'} />
        }
    ]
};

export default LoginRoutes;
