// assets
import { SettingOutlined } from '@ant-design/icons';
// icons
const icons = {
    SettingOutlined
};

// ==============================|| MENU ITEMS - EXTRA PAGES ||============================== //

const settings = {
    id: 'settings',
    title: 'Settings',
    privilege: 'manage_settings',
    type: 'group',
    children: [
        {
            id: 'settings',
            title: 'Settings',
            type: 'item',
            url: '/settings',
            icon: icons.SettingOutlined
        }
    ]
};

export default settings;
