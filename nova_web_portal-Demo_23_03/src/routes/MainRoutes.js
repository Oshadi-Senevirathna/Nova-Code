import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MainLayout from 'layout/MainLayout';

const DashboardDefault = Loadable(lazy(() => import('pages/dashboard')));

// render - settings page
const LogsPage = Loadable(lazy(() => import('pages/user-logs')));

// render - reporting page
const ReportingPage = Loadable(lazy(() => import('pages/reporting')));

// ==============================|| MAIN ROUTING ||============================== //

const MainRoutes = {
    path: '/',
    element: <MainLayout />,
    children: [
        {
            path: '/',
            element: <DashboardDefault title={'Nova | Dashboard'} />
        },
        {
            path: 'dashboard',
            children: [
                {
                    path: 'default',
                    element: <DashboardDefault title={'Nova | Dashboard'} />
                }
            ]
        },
        {
            path: 'logs',
            element: <LogsPage title={'Nova | Logs'} />
        },
        {
            path: 'reporting',
            element: <ReportingPage title={'Nova | Reporting'} />
        }
    ]
};

export default MainRoutes;
