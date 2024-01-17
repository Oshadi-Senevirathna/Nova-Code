import main from './main';
import inventory from './inventory';
import orchestration from './orchestration';
import vnf from './vnf';
import users from './users';
import logs from './logs';
import settings from './settings';
import companies from './companies';

// ==============================|| MENU ITEMS ||============================== //

const menuItems = {
    items: [main, inventory, orchestration, vnf, users, settings, logs, companies]
};

export default menuItems;
