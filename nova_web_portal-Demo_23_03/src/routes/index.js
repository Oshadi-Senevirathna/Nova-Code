import { useRoutes } from 'react-router-dom';
import { useState, useEffect } from 'react';
// project import
import DefaultRoute from './DefaultRoute';

import LoginRoutes from './LoginRoutes';

import MainRoutes from './MainRoutes';
import InventoryRoutes from './InventoryRoutes';
import OrchestrationRoutes from './OrchestrationRoutes';
import VnfRoutes from './VnfRoutes';
import UserRoutes from './UserRoutes';
import SettingsRoutes from './SettingsRoutes';
import CompaniesRoutes from './CompaniesRoutes';

import serviceFactoryInstance from 'framework/services/service-factory';

// ==============================|| ROUTING RENDER ||============================== //

const ThemeRoutes = () => {
    const [routeList, setRouteList] = useState([LoginRoutes]);
    useEffect(() => {
        serviceFactoryInstance.authService.getUserObservable().subscribe((user) => {
            if (!user) {
                if (!localStorage.getItem('currentUser')) {
                    setRouteList([LoginRoutes, DefaultRoute]);
                }
            } else {
                var tempRouteList = [];
                tempRouteList = [MainRoutes];
                if (serviceFactoryInstance.authService && serviceFactoryInstance.authService.hasPrivilege('manage_inventory')) {
                    tempRouteList = [...tempRouteList, InventoryRoutes];
                }
                if (serviceFactoryInstance.authService && serviceFactoryInstance.authService.hasPrivilege('manage_orchestration')) {
                    tempRouteList = [...tempRouteList, OrchestrationRoutes];
                }
                if (serviceFactoryInstance.authService && serviceFactoryInstance.authService.hasPrivilege('manage_vnf')) {
                    tempRouteList = [...tempRouteList, VnfRoutes];
                }
                if (serviceFactoryInstance.authService && serviceFactoryInstance.authService.hasPrivilege('manage_users')) {
                    tempRouteList = [...tempRouteList, UserRoutes];
                }
                if (serviceFactoryInstance.authService && serviceFactoryInstance.authService.hasPrivilege('manage_settings')) {
                    tempRouteList = [...tempRouteList, SettingsRoutes];
                }
                if (serviceFactoryInstance.authService && serviceFactoryInstance.authService.hasPrivilege('manage_companies')) {
                    tempRouteList = [...tempRouteList, CompaniesRoutes];
                }
                setRouteList([...tempRouteList, DefaultRoute]);
            }
        });
    }, []);

    return useRoutes(routeList);
};

export default ThemeRoutes;
