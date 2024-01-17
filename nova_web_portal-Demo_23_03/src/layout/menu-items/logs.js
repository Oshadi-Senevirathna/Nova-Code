// assets
import { UnorderedListOutlined } from '@ant-design/icons';
// icons
const icons = {
    UnorderedListOutlined
};

// ==============================|| MENU ITEMS - EXTRA PAGES ||============================== //

const logs = {
    id: 'logs',
    title: 'Logs',
    // privilege: 'manage_logs',
    type: 'group',
    children: [
        {
            id: 'logs',
            title: 'Logs',
            type: 'item',
            url: '/logs',
            icon: icons.UnorderedListOutlined
        }
    ]
};

export default logs;
