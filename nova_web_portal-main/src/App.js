// project import
import Routes from 'routes';
import ThemeCustomization from 'themes';
import ScrollTop from 'components/ScrollTop';
import serviceFactoryInstance from 'framework/services/service-factory';

// ==============================|| APP - THEME, ROUTER, LOCAL  ||============================== //

const App = () => {
    const serviceFactory = serviceFactoryInstance;
    serviceFactory.init();
    return (
        <ThemeCustomization>
            <ScrollTop>
                <Routes />
            </ScrollTop>
        </ThemeCustomization>
    );
};

export default App;
