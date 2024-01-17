// assets
import { DashboardOutlined, UnorderedListOutlined, AreaChartOutlined } from '@ant-design/icons';
// icons
const icons = {
    DashboardOutlined,
    UnorderedListOutlined,
    AreaChartOutlined
};

// ==============================|| MENU ITEMS - EXTRA PAGES ||============================== //

const main = {
    id: 'group-dashboard',
    title: 'Navigation',
    type: 'group',
    children: [
        {
            id: 'dashboard',
            title: 'Dashboard',
            type: 'item',
            url: '/dashboard/default',
            icon: icons.DashboardOutlined,
            breadcrumbs: false
        },
        // {
        //     id: 'logs',
        //     title: 'Logs',
        //     type: 'item',
        //     url: '/logs',
        //     icon: icons.UnorderedListOutlined
        // },
        {
            id: 'reporting',
            title: 'Reporting',
            type: 'item',
            url: '/reporting',
            icon: icons.AreaChartOutlined
        }
    ]
};

export default main;
