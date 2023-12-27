import { useState } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';
import { Dialog, DialogTitle, DialogContent } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, OutlinedInput, Stack } from '@mui/material';
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';

// ============================|| FIREBASE - LOGIN ||============================ //

const SimpleJobForm = ({ formOpen, closeForm }) => {
    const [initialValues, setInitialValues] = useState({
        value_a: '',
        value_b: ''
    });

    const cleanCloseForm = () => {
        closeForm();
        setInitialValues({
            value_a: '',
            value_b: ''
        });
    };

    return (
        <>
            <Dialog style={{ width: '50%', margin: 'auto' }} open={formOpen} onClose={cleanCloseForm} fullWidth>
                <DialogTitle>Simple Division Job Form</DialogTitle>
                <DialogContent>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            var job = {};
                            var args = [];
                            job.job_name = 'simple_division_job_new';
                            args.push(values.value_a);
                            args.push(values.value_a);
                            job.arguments = args;

                            setSubmitting(true);
                            serviceFactoryInstance.dataLoaderService
                                .addInstance(ENTITY_NAME_FRONTEND_JOBS, job)
                                .then((data) => {
                                    if (data.status) {
                                        cleanCloseForm();
                                        setSubmitting(false);
                                    } else {
                                        setErrors({ submit: data.reason });
                                        setSubmitting(false);
                                    }
                                })
                                .catch((reason) => {
                                    setErrors({ submit: reason });
                                    setSubmitting(false);
                                });
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="job-form-value-a">Value A</InputLabel>
                                            <OutlinedInput
                                                id="inventory-form-value-a"
                                                type="text"
                                                value={values.value_a}
                                                name="value_a"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter value A"
                                                fullWidth
                                                error={Boolean(touched.value_a && errors.value_a)}
                                            />
                                            {touched.value_a && errors.value_a && (
                                                <FormHelperText error id="standard-weight-helper-text-inventory-form-value-a">
                                                    {errors.value_a}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="inventory-form-value-b">Value B</InputLabel>
                                            <OutlinedInput
                                                id="inventory-form-value-b"
                                                type="text"
                                                value={values.value_b}
                                                name="value_b"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter value B"
                                                fullWidth
                                                error={Boolean(touched.value_b && errors.value_b)}
                                            />
                                            {touched.value_b && errors.value_b && (
                                                <FormHelperText error id="standard-weight-helper-text-inventory-form-value-b">
                                                    {errors.value_b}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    {errors.submit && (
                                        <Grid item xs={12}>
                                            <FormHelperText error>{errors.submit}</FormHelperText>
                                        </Grid>
                                    )}
                                    <Grid item xs={12} md={6}>
                                        <AnimateButton>
                                            <Button
                                                disableElevation
                                                disabled={isSubmitting}
                                                fullWidth
                                                size="large"
                                                type="submit"
                                                variant="contained"
                                                color="primary"
                                            >
                                                {'Add'}
                                            </Button>
                                        </AnimateButton>
                                    </Grid>
                                    <Grid item xs={12} md={6}>
                                        <AnimateButton>
                                            <Button
                                                onClick={cleanCloseForm}
                                                disableElevation
                                                fullWidth
                                                size="large"
                                                variant="contained"
                                                color="primary"
                                                type="button"
                                            >
                                                Cancel
                                            </Button>
                                        </AnimateButton>
                                    </Grid>
                                </Grid>
                            </form>
                        )}
                    </Formik>
                </DialogContent>
            </Dialog>
        </>
    );
};

export default SimpleJobForm;
