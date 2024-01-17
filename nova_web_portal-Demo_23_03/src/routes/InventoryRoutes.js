import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MainLayout from 'layout/MainLayout';

const InventoryPage = Loadable(lazy(() => import('pages/inventory')));
const InventoryDetailsPage = Loadable(lazy(() => import('pages/inventory/inventory-details.js')));
const InventoryLogsPage = Loadable(lazy(() => import('pages/inventory/inventory-logs.js')));

// ==============================|| MAIN ROUTING ||============================== //

const InventoryRoutes = {
    path: '/',
    element: <MainLayout />,
    children: [
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
        }
    ]
};

export default InventoryRoutes;
