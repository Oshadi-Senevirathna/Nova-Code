import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MainLayout from 'layout/MainLayout';

// render - dashboard
const DashboardDefault = Loadable(lazy(() => import('pages/dashboard')));

// render - settings page
const SettingsPage = Loadable(lazy(() => import('pages/settings')));

// render - settings page
const LogsPage = Loadable(lazy(() => import('pages/user-logs')));

// render - inventory page
const InventoryPage = Loadable(lazy(() => import('pages/inventory')));
const InventoryDetailsPage = Loadable(lazy(() => import('pages/inventory/inventory-details.js')));
const InventoryLogsPage = Loadable(lazy(() => import('pages/inventory/inventory-logs.js')));

// render - inventory page
const VMImagesPage = Loadable(lazy(() => import('pages/vm-images')));

// render - inventory page
const VMTemplatesDetails = Loadable(lazy(() => import('pages/vm-templates/vm-template-details.js')));
const VMTemplatesPage = Loadable(lazy(() => import('pages/vm-templates')));

//render - tenant page
const TenantPage = Loadable(lazy(() => import('pages/tenant')));

//render - company page
const CompanyPage = Loadable(lazy(() => import('pages/company')));

// render - users page
const UsersPage = Loadable(lazy(() => import('pages/users')));
const UserDetails = Loadable(lazy(() => import('pages/users/user-details.js')));

// render - orchestration page
const OrchestrationPage = Loadable(lazy(() => import('pages/orchestration')));

// render - jobs page
const JobsPage = Loadable(lazy(() => import('pages/jobs')));
const JobDetails = Loadable(lazy(() => import('pages/jobs/job-details.js')));

// render - utilities
const Typography = Loadable(lazy(() => import('pages/components-overview/Typography')));
const Color = Loadable(lazy(() => import('pages/components-overview/Color')));
const Shadow = Loadable(lazy(() => import('pages/components-overview/Shadow')));
const AntIcons = Loadable(lazy(() => import('pages/components-overview/AntIcons')));

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
            path: 'color',
            element: <Color />
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
            path: 'settings',
            element: <SettingsPage title={'Nova | Settings'} />
        },
        {
            path: 'Orchestration',
            element: <OrchestrationPage title={'Nova | Orchestration'} />
        },
        {
            path: 'inventory/details/:UUID',
            element: <InventoryDetailsPage title={'Nova | Inventory'} />
        },
        {
            path: 'inventory/devicelogs/:UUID',
            element: <InventoryLogsPage title={'Nova | Inventory'} />
        },
        {
            path: 'inventory',
            element: <InventoryPage title={'Nova | Inventory'} />
        },
        {
            path: 'logs',
            element: <LogsPage title={'Nova | Logs'} />
        },
        {
            path: 'vmimages',
            element: <VMImagesPage title={'Nova | vmimages'} />
        },
        {
            path: 'vmtemplates/details/:UUID',
            element: <VMTemplatesDetails title={'Nova | vmtemplates'} />
        },
        {
            path: 'vmtemplates/details',
            element: <VMTemplatesDetails title={'Nova | vmtemplates'} />
        },
        {
            path: 'vmtemplates',
            element: <VMTemplatesPage title={'Nova | vmtemplates'} />
        },
        {
            path: 'tenants',
            element: <TenantPage title={'Nova | Tenants'} />
        },
        {
            path: 'companies',
            element: <CompanyPage title={'Nova | Companies'} />
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
        },
        {
            path: 'jobs/details/:UUID',
            element: <JobDetails title={'Nova | Jobs'} />
        },
        {
            path: 'jobs',
            element: <JobsPage title={'Nova | Jobs'} />
        },
        {
            path: 'shadow',
            element: <Shadow />
        },
        {
            path: 'typography',
            element: <Typography />
        },
        {
            path: 'icons/ant',
            element: <AntIcons />
        }
    ]
};

export default MainRoutes;
