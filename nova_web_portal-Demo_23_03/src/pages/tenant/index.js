import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Button } from '@mui/material';
import { ENTITY_NAME_TENANT } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import { useEffect, useState } from 'react';
import configs from './tenant-config.json';
import TenantForm from './tenant-form';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import CustomDatatable from 'components/styledMUI/Datatable';

const useStyles = makeStyles((theme) => ({
    root: {
        flexGrow: 1,
        width: '100%',
        margin: 0,
        padding: 0
    },
    progressBar: {
        marginTop: '20px',
        marginBottom: '20px',
        marginRight: '20px'
    },
    button: {
        marginRight: '20px',
        marginTop: '10px',
        width: '120px'
    },
    iconbutton: {
        marginRight: '20px',
        marginTop: '10px',
        width: '30px'
    }
}));

const InventoryPage = ({ title }) => {
    const classes = useStyles();
    const [UUID, setUUID] = useState();
    const [formOpen, setFormOpen] = useState(false);
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');

    useEffect(() => {
        document.title = title;
    }, []);

    var configReshaped = configs;

    const closeForm = () => {
        setUUID();
        setFormOpen(false);
    };

    const openForm = () => {
        setFormOpen(true);
    };

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_TENANT, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete tenant successful');
                    } else {
                        setErrorSnackbarMessage('Delete tenant failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete tenant failed');
                });
        }
    };

    return (
        <div className={classes.root}>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <CustomDatatable
                entityName={ENTITY_NAME_TENANT}
                configs={configReshaped}
                deleteData={deleteData}
                setUUID={setUUID}
                openForm={openForm}
            />

            <TenantForm
                formOpen={formOpen}
                closeForm={closeForm}
                UUID={UUID}
                setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
            />
            <Button size="medium" variant="contained" color="primary" onClick={() => openForm()} className={classes.button}>
                Add
            </Button>
        </div>
    );
};

export default InventoryPage;
