import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { useEffect, useState } from 'react';
import InventoryReportingForm from './inventory-reporting-form';
import JobsReportingForm from './jobs-reporting-form';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import { Accordion, AccordionDetails, AccordionSummary, Typography } from '../../../node_modules/@mui/material/index';
import { CaretDownOutlined } from '@ant-design/icons';
import { Grid } from '../../../node_modules/@mui/material/index';
const useStyles = makeStyles((theme) => ({
    root: {
        flexGrow: 1,
        width: '100%',
        marginLeft: '0',
        marginRight: '0'
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

    const [inventoryReportingFormOpen, setInventoryReportingFormOpen] = useState(false);
    const [jobReportingFormOpen, setJobReportingFormOpen] = useState(false);

    return (
        <Grid item width="100%">
            <Grid item>
                <CustomSnackbar
                    msg={successSnackbarMessage}
                    onClose={() => setSuccessSnackbarMessage('')}
                    severity="success"
                    title="Success"
                />
                <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
                <Accordion
                    key={'inventory-reporting-form-accordian'}
                    expanded={inventoryReportingFormOpen}
                    onChange={() => setInventoryReportingFormOpen(!inventoryReportingFormOpen)}
                >
                    <AccordionSummary className={classes.accordian} expandIcon={<CaretDownOutlined />}>
                        <Typography variant="h6">Inventory Reporting</Typography>
                    </AccordionSummary>
                    <AccordionDetails key={'vm-create-form'}>
                        <InventoryReportingForm />
                    </AccordionDetails>
                </Accordion>
                <Accordion
                    key={'job-reporting-form-accordian'}
                    expanded={jobReportingFormOpen}
                    onChange={() => setJobReportingFormOpen(!jobReportingFormOpen)}
                >
                    <AccordionSummary className={classes.accordian} expandIcon={<CaretDownOutlined />}>
                        <Typography variant="h6">Job Reporting</Typography>
                    </AccordionSummary>
                    <AccordionDetails key={'vm-create-form'}>
                        <JobsReportingForm />
                    </AccordionDetails>
                </Accordion>
            </Grid>
        </Grid>
    );
};

export default OrchestrationPage;
