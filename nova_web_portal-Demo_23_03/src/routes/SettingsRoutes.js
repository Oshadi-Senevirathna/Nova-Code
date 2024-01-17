import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MainLayout from 'layout/MainLayout';

// render - settings page
const SettingsPage = Loadable(lazy(() => import('pages/settings')));

// ==============================|| MAIN ROUTING ||============================== //

const SettingsRoutes = {
    path: '/',
    element: <MainLayout />,
    children: [
        {
            path: 'settings',
            element: <SettingsPage title={'Nova | Settings'} />
        }
    ]
};

export default SettingsRoutes;
