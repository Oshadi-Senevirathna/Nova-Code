// assets
import { ReconciliationOutlined } from '@ant-design/icons';
// icons
const icons = {
    ReconciliationOutlined
};

// ==============================|| MENU ITEMS - EXTRA PAGES ||============================== //

const inventory = {
    id: 'inventory',
    title: 'Inventory',
    type: 'group',
    privilege: 'manage_inventory',
    children: [
        {
            id: 'inventory',
            title: 'Inventory',
            type: 'item',
            url: '/inventory',
            icon: icons.ReconciliationOutlined
        },
        {
            id: 'inventory_details',
            title: 'Device Details',
            type: 'crumb',
            url: '/inventory/details',
            icon: icons.ReconciliationOutlined
        },
        {
            id: 'inventory_logs',
            title: 'Inventory Logs',
            type: 'crumb',
            url: '/inventory/devicelogs',
            icon: icons.ReconciliationOutlined
        }
    ]
};

export default inventory;
