import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MainLayout from 'layout/MainLayout';

//render - company page
const RolesPage = Loadable(lazy(() => import('pages/roles')));
const RolesDetails = Loadable(lazy(() => import('pages/roles/role-details.js')));

// render - users page
const UsersPage = Loadable(lazy(() => import('pages/users')));
const UserDetails = Loadable(lazy(() => import('pages/users/user-details.js')));

// ==============================|| MAIN ROUTING ||============================== //

const UserRoutes = {
    path: '/',
    element: <MainLayout />,
    children: [
        {
            path: 'roles/details/:UUID',
            element: <RolesDetails title={'Nova | Roles'} />
        },
        {
            path: 'roles/details',
            element: <RolesDetails title={'Nova | Roles'} />
        },
        {
            path: 'roles',
            element: <RolesPage title={'Nova | Roles'} />
        },
        {
            path: 'users/details/:UUID',
            element: <UserDetails title={'Nova | Users'} />
        },
        {
            path: 'users/details',
            element: <UserDetails title={'Nova | Users'} />
        },
        {
            path: 'users',
            element: <UsersPage title={'Nova | Users'} />
        }
    ]
};

export default UserRoutes;
