import { useRoutes } from 'react-router-dom';

// project import
import LoginRoutes from './LoginRoutes';
import MainRoutes from './MainRoutes';
import serviceFactoryInstance from 'framework/services/service-factory';

// ==============================|| ROUTING RENDER ||============================== //

export default function ThemeRoutes() {
    return useRoutes(!serviceFactoryInstance.authService.isLoggedIn() ? [LoginRoutes] : [MainRoutes]);
}
