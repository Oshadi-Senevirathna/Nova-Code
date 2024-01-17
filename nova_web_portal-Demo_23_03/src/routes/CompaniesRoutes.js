import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MainLayout from 'layout/MainLayout';

//render - tenant page
const TenantPage = Loadable(lazy(() => import('pages/tenant')));

//render - company page
const CompanyPage = Loadable(lazy(() => import('pages/company')));

// ==============================|| MAIN ROUTING ||============================== //

const CompaniesRoutes = {
    path: '/',
    element: <MainLayout />,
    children: [
        {
            path: 'tenants',
            element: <TenantPage title={'Nova | Tenants'} />
        },
        {
            path: 'companies',
            element: <CompanyPage title={'Nova | Companies'} />
        }
    ]
};

export default CompaniesRoutes;
