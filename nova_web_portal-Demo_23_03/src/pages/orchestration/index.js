import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { useEffect, useState } from 'react';
import CreateVMForm from './create-vm-form';
import DestroyVMForm from './destroy-vm-form';
import UpgradeVMForm from './upgrade-vm-form';
import DowngradeVMForm from './downgrade-vm-form';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import { Accordion, AccordionDetails, AccordionSummary, Typography } from '../../../node_modules/@mui/material/index';
import { CaretDownOutlined } from '@ant-design/icons';

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
    },
    accordian: {
        cursor: 'pointer',
        '&:hover': {
            background: '#ebebeb'
        }
    }
}));

const OrchestrationPage = ({ title }) => {
    const classes = useStyles();
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');

    useEffect(() => {
        document.title = title;
    }, []);

    const [vmCreateFormOpen, setVmCreateFormOpen] = useState(false);
    const closeVmCreateForm = () => {
        setVmCreateFormOpen(false);
    };

    const [vmDestroyFormOpen, setVmDestroyFormOpen] = useState(false);
    const closeVmDestroyForm = () => {
        setVmDestroyFormOpen(false);
    };

    const [vmUpgradeFormOpen, setVmUpgradeFormOpen] = useState(false);
    const closeVmUpgradeForm = () => {
        setVmUpgradeFormOpen(false);
    };

    const [vmDowngradeFormOpen, setVmDowngradeFormOpen] = useState(false);
    const closeVmDowngradeForm = () => {
        setVmDowngradeFormOpen(false);
    };

    return (
        <div className={classes.root}>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <Accordion key={'vm-create-form-accordian'} expanded={vmCreateFormOpen} onChange={() => setVmCreateFormOpen(!vmCreateFormOpen)}>
                <AccordionSummary className={classes.accordian} expandIcon={<CaretDownOutlined />}>
                    <Typography variant="h6">Create VNF Form</Typography>
                </AccordionSummary>
                <AccordionDetails key={'vm-create-form'}>
                    <CreateVMForm
                        formOpen={vmCreateFormOpen}
                        closeForm={closeVmCreateForm}
                        setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                        setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
                    />
                </AccordionDetails>
            </Accordion>
            <Accordion
                key={'vm-destroy-form-accordian'}
                expanded={vmDestroyFormOpen}
                onChange={() => setVmDestroyFormOpen(!vmDestroyFormOpen)}
            >
                <AccordionSummary className={classes.accordian} expandIcon={<CaretDownOutlined />}>
                    <Typography variant="h6">Destroy VNF Form</Typography>
                </AccordionSummary>
                <AccordionDetails key={'vm-destroy-form'}>
                    <DestroyVMForm
                        formOpen={vmDestroyFormOpen}
                        closeForm={closeVmDestroyForm}
                        setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                        setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
                    />
                </AccordionDetails>
            </Accordion>
            <Accordion
                key={'vm-upgrade-form-accordian'}
                expanded={vmUpgradeFormOpen}
                onChange={() => setVmUpgradeFormOpen(!vmUpgradeFormOpen)}
            >
                <AccordionSummary className={classes.accordian} expandIcon={<CaretDownOutlined />}>
                    <Typography variant="h6">Upgrade VNF Form</Typography>
                </AccordionSummary>
                <AccordionDetails key={'vm-upgrade-form'}>
                    <UpgradeVMForm
                        formOpen={vmUpgradeFormOpen}
                        closeForm={closeVmUpgradeForm}
                        setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                        setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
                    />
                </AccordionDetails>
            </Accordion>
            <Accordion
                key={'vm-downgrade-form-accordian'}
                expanded={vmDowngradeFormOpen}
                onChange={() => setVmDowngradeFormOpen(!vmDowngradeFormOpen)}
            >
                <AccordionSummary className={classes.accordian} expandIcon={<CaretDownOutlined />}>
                    <Typography variant="h6">Downgrade VNF Form</Typography>
                </AccordionSummary>
                <AccordionDetails key={'vm-downgrade-form'}>
                    <DowngradeVMForm
                        formOpen={vmDowngradeFormOpen}
                        closeForm={closeVmDowngradeForm}
                        setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                        setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
                    />
                </AccordionDetails>
            </Accordion>
        </div>
    );
};

export default OrchestrationPage;
