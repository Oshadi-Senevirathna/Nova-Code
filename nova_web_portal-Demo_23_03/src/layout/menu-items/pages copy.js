// assets
import {
    LoginOutlined,
    ProfileOutlined,
    SettingOutlined,
    ReconciliationOutlined,
    UserOutlined,
    IdcardFilled,
    CarryOutOutlined,
    LaptopOutlined,
    UnorderedListOutlined,
    ContainerOutlined,
    ClockCircleOutlined,
    BankOutlined,
    AreaChartOutlined,
    ControlOutlined,
    DashboardOutlined,
    UnorderedListOutlined,
    AreaChartOutlined
} from '@ant-design/icons';
// icons
const icons = {
    LoginOutlined,
    ProfileOutlined,
    SettingOutlined,
    ReconciliationOutlined,
    UserOutlined,
    CarryOutOutlined,
    IdcardFilled,
    LaptopOutlined,
    UnorderedListOutlined,
    ContainerOutlined,
    ClockCircleOutlined,
    BankOutlined,
    AreaChartOutlined,
    ControlOutlined,
    DashboardOutlined,
    UnorderedListOutlined,
    AreaChartOutlined
};

// ==============================|| MENU ITEMS - EXTRA PAGES ||============================== //

const pages = {
    id: 'application',
    title: 'Application',
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
        },
        {
            id: 'vm_images',
            title: 'VNF Images',
            type: 'item',
            url: '/vmimages',
            icon: icons.LaptopOutlined
        },
        {
            id: 'vm_templates',
            title: 'VNF Templates',
            type: 'item',
            url: '/vmtemplates',
            icon: icons.ContainerOutlined
        },
        {
            id: 'vm_templates_details',
            title: 'VNF Templates Details',
            type: 'crumb',
            url: '/vmtemplates/details',
            icon: icons.ContainerOutlined
        },
        {
            id: 'Orchestration',
            title: 'Orchestration',
            type: 'item',
            url: '/orchestration',
            icon: icons.ClockCircleOutlined
        },
        {
            id: 'jobs',
            title: 'Jobs',
            type: 'item',
            url: '/jobs',
            icon: icons.CarryOutOutlined
        },
        {
            id: 'job_details',
            title: 'Job Details',
            type: 'crumb',
            url: '/jobs/details',
            icon: icons.CarryOutOutlined
        },
        {
            id: 'tenants',
            title: 'Tenants',
            type: 'item',
            url: '/tenants',
            icon: icons.IdcardFilled
        },
        {
            id: 'company',
            title: 'Companies',
            type: 'item',
            url: '/companies',
            icon: icons.BankOutlined
        },
        {
            id: 'roles',
            title: 'Roles',
            type: 'item',
            url: '/roles',
            icon: icons.ControlOutlined
        },
        {
            id: 'role_details',
            title: 'Role Details',
            type: 'crumb',
            url: '/roles/details',
            icon: icons.ControlOutlined
        },
        {
            id: 'users',
            title: 'Users',
            type: 'item',
            url: '/users',
            icon: icons.UserOutlined
        },
        {
            id: 'user_details',
            title: 'User Details',
            type: 'crumb',
            url: '/users/details',
            icon: icons.UserOutlined
        },
        {
            id: 'settings',
            title: 'Settings',
            type: 'item',
            url: '/settings',
            icon: icons.SettingOutlined
        },
        {
            id: 'logs',
            title: 'Logs',
            type: 'item',
            url: '/logs',
            icon: icons.UnorderedListOutlined
        },
        {
            id: 'reporting',
            title: 'Reporting',
            type: 'item',
            url: '/reporting',
            icon: icons.AreaChartOutlined
        }
    ]
};

export default pages;
