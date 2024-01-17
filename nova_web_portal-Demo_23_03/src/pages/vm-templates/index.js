import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ENTITY_NAME_VM_TEMPLATES } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './vm-template-config.json';
import { Button } from '../../../node_modules/@mui/material/index';
import { Grid } from '../../../node_modules/@mui/material/index';
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

const VMTemplatePage = ({ title }) => {
    const classes = useStyles();
    const navigate = useNavigate();
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');

    useEffect(() => {
        document.title = title;
    }, []);

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_VM_TEMPLATES, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete vm template successful');
                    } else {
                        setErrorSnackbarMessage('Delete vm template failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete vm template failed');
                });
        }
    };

    return (
        <div className={classes.root}>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <CustomDatatable
                entityName={ENTITY_NAME_VM_TEMPLATES}
                configs={configs}
                deleteData={deleteData}
                navigateToPage={(UUID) => navigate(`/vmtemplates/details/${UUID}`)}
            />
            <Grid container style={{ justifyItems: 'center' }}>
                <Grid item xs={12} style={{ padding: 20 }}>
                    <Button size="medium" fullWidth variant="contained" color="primary" onClick={() => navigate(`/vmtemplates/details`)}>
                        Add VNF template
                    </Button>
                </Grid>
            </Grid>
        </div>
    );
};

export default VMTemplatePage;
