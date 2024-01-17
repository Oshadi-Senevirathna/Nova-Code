import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Button, Grid } from '@mui/material';
import { ENTITY_NAME_COMPANY } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import { useEffect, useState } from 'react';
import configs from './company-config.json';
import CompanyForm from './company-form';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import AnimateButton from 'components/@extended/AnimateButton';
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

const CompanyPage = ({ title }) => {
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
                .deleteInstance(ENTITY_NAME_COMPANY, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete company successful');
                    } else {
                        setErrorSnackbarMessage('Delete company failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete company failed');
                });
        }
    };

    return (
        <div className={classes.root}>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <CustomDatatable
                entityName={ENTITY_NAME_COMPANY}
                configs={configReshaped}
                deleteData={deleteData}
                setUUID={setUUID}
                openForm={openForm}
            />
            <CompanyForm
                formOpen={formOpen}
                closeForm={closeForm}
                UUID={UUID}
                setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
            />
            <Grid item xs={12} marginTop={2}>
                <AnimateButton>
                    <Button fullWidth size="large" variant="contained" color="primary" type="button" onClick={() => openForm()}>
                        Add
                    </Button>
                </AnimateButton>
            </Grid>
        </div>
    );
};

export default CompanyPage;
