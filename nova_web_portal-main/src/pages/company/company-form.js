import { useEffect, useState } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_COMPANY, ENTITY_NAME_TENANT } from 'framework/caching/entity-cache';
import { Dialog, DialogTitle, DialogContent } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, OutlinedInput, Stack } from '@mui/material';
// third party
import * as Yup from 'yup';
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
import Multiselect from '../../../node_modules/multiselect-react-dropdown/dist/index';

// ============================|| FIREBASE - LOGIN ||============================ //

const CompanyForm = ({ formOpen, closeForm, UUID, setSuccessSnackbarMessage, setErrorSnackbarMessag }) => {
    const [selectedTenants, setSelectedTenants] = useState([]);
    const [tenants, setTenants] = useState([]);
    const [initialValues, setInitialValues] = useState({
        instance_name: '',
        address_1: '',
        address_2: ''
    });

    useEffect(() => {
        if (UUID !== undefined) {
            //edit an existing instance
            serviceFactoryInstance.dataLoaderService.getInstance(UUID, ENTITY_NAME_COMPANY).then((data) => {
                if (data.status) {
                    var temp = {};
                    temp['instance_name'] = data.instance.instance_name;
                    temp['UUID'] = data.instance.UUID;
                    temp['address_1'] = data.instance.address_1;
                    temp['address_2'] = data.instance.address_2;
                    setSelectedTenants(data.instance.tenants);
                    setInitialValues(temp);
                }
            });
        }
    }, [UUID]);

    useEffect(() => {
        const tenantsSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_TENANT}>summary`).subscribe((data) => {
            if (data) {
                setTenants(data);
            }
        });
        return () => {
            tenantsSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const onSelect = (selectedList, selectedItem) => {
        setSelectedTenants([...selectedList]);
    };

    const onRemove = (selectedList, removedItem) => {
        var selectedListTemp = [...selectedList];
        const position = selectedList.indexOf(removedItem);
        if (position !== -1) {
            selectedListTemp.splice(position, 1);
        }
        setSelectedTenants(selectedListTemp);
    };

    const cleanCloseForm = () => {
        closeForm();
        setSelectedTenants([]);
        setInitialValues({
            instance_name: '',
            address_1: '',
            address_2: '',
            tenants: []
        });
    };

    return (
        <>
            <Dialog style={{ width: '50%', margin: 'auto' }} open={formOpen} onClose={cleanCloseForm} fullWidth>
                <DialogTitle>Company Form</DialogTitle>
                <DialogContent>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        validationSchema={Yup.object().shape({
                            instance_name: Yup.string().required('Company name is required')
                        })}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            var temp = { ...values };
                            temp.tenants = selectedTenants;
                            console.log(temp);
                            UUID
                                ? serviceFactoryInstance.dataLoaderService
                                      .updateInstance(ENTITY_NAME_COMPANY, temp)
                                      .then((data) => {
                                          if (data.status) {
                                              cleanCloseForm();
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully edited company');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessag('Edit company failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessag('Edit company failed');
                                      })
                                : serviceFactoryInstance.dataLoaderService
                                      .addInstance(ENTITY_NAME_COMPANY, temp)
                                      .then((data) => {
                                          if (data.status) {
                                              cleanCloseForm();
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully added company');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessag('Add company failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessag('Add company failed');
                                      });
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="company-form-instance_name">Company Name</InputLabel>
                                            <OutlinedInput
                                                id="company-form-instance_name"
                                                type="text"
                                                value={values.instance_name}
                                                name="instance_name"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter hostname"
                                                fullWidth
                                                error={Boolean(touched.instance_name && errors.instance_name)}
                                            />
                                            {touched.instance_name && errors.instance_name && (
                                                <FormHelperText error id="standard-weight-helper-text-company-form-instance_name">
                                                    {errors.instance_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="company-form-address_1">Address Line 1</InputLabel>
                                            <OutlinedInput
                                                id="company-form-address_1"
                                                type="text"
                                                value={values.address_1}
                                                name="address_1"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter address line 1"
                                                fullWidth
                                                error={Boolean(touched.address_1 && errors.address_1)}
                                            />
                                            {touched.address_1 && errors.address_1 && (
                                                <FormHelperText error id="standard-weight-helper-text-company-form-address_1">
                                                    {errors.address_1}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="company-form-address_2">Address Line 2</InputLabel>
                                            <OutlinedInput
                                                id="company-form-address_2"
                                                type="text"
                                                value={values.address_2}
                                                name="address_2"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter address line 2"
                                                fullWidth
                                                error={Boolean(touched.address_2 && errors.address_2)}
                                            />
                                            {touched.address_2 && errors.address_2 && (
                                                <FormHelperText error id="standard-weight-helper-text-company-form-address_2">
                                                    {errors.address_2}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1} style={{ height: 200 }}>
                                            <InputLabel htmlFor="company-form-tenants">Select tenants to apply template</InputLabel>
                                            <Multiselect
                                                showCheckbox={true}
                                                options={tenants} // Options to display in the dropdown
                                                selectedValues={selectedTenants} // Preselected value to persist in dropdown
                                                onSelect={onSelect} // Function will trigger on select event
                                                onRemove={onRemove} // Function will trigger on remove event
                                                displayValue="instance_name" // Property name to display in the dropdown options
                                            />
                                            {touched.tenants && errors.tenants && (
                                                <FormHelperText error id="standard-weight-helper-text-company-form-tenants">
                                                    {errors.tenants}
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
                                                {!UUID ? 'Add Company' : 'Save'}
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

export default CompanyForm;
