// assets
import { CarryOutOutlined, ClockCircleOutlined } from '@ant-design/icons';
// icons
const icons = {
    CarryOutOutlined,
    ClockCircleOutlined
};

// ==============================|| MENU ITEMS - EXTRA PAGES ||============================== //

const orchestration = {
    id: 'orchestration',
    title: 'Orchestraion',
    type: 'group',
    privilege: 'manage_orchestration',
    children: [
        {
            id: 'orchestration',
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
        }
    ]
};

export default orchestration;
