import { useState, useEffect } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_DEVICE, ENTITY_NAME_VM_TEMPLATES, ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';
import { Select, MenuItem } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, Stack } from '@mui/material';
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
// material-ui
import * as Yup from 'yup';
import Multiselect from '../../../node_modules/multiselect-react-dropdown/dist/index';

// ============================|| FIREBASE - LOGIN ||============================ //

const CreateVMForm = ({ closeForm, setSuccessSnackbarMessage, setErrorSnackbarMessage }) => {
    const [initialValues, setInitialValues] = useState({
        device_id: '',
        template_id: ''
    });
    const [devices, setDevices] = useState();
    const [devicesWithAll, setDevicesWithAll] = useState();
    const [templates, setTemplates] = useState();
    const [selectedDevices, setSelectedDevices] = useState([]);
    const [tenant, setTenant] = useState();
    useEffect(() => {
        const tenantSub = serviceFactoryInstance.authService.getTenantObservable().subscribe((tenant) => {
            setTenant(tenant);
        });
        return () => {
            tenantSub.unsubscribe();
        };
    }, [serviceFactoryInstance.authService]);

    var temp = {};
    temp.UUID = 0;
    temp.instance_name = 'Select All';

    useEffect(() => {
        const devicesSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_DEVICE, tenant).subscribe((data) => {
            if (data) {
                setDevicesWithAll([temp, ...data]);
                setDevices(data);
            }
        });

        const templatesSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_VM_TEMPLATES}>summary`).subscribe((data) => {
            if (data) {
                setTemplates(data);
            }
        });

        return () => {
            devicesSub.unsubscribe();
            templatesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache, tenant]);

    const cleanCloseForm = () => {
        closeForm();
        setInitialValues({
            device_id: '',
            template_id: ''
        });
    };

    const onSelect = (selectedList, selectedItem, allOptions, variableSet) => {
        if (selectedItem.UUID === 0) {
            variableSet([temp, ...allOptions]);
        } else if (selectedList.length === allOptions.length) {
            variableSet([temp, ...allOptions]);
        } else {
            variableSet([...selectedList]);
        }
    };

    const onRemove = (selectedList, removedItem, allOptions, variableSet) => {
        if (removedItem.UUID === 0) {
            variableSet([]);
        } else {
            var temp = [];
            for (let i = 0; i < selectedList.length; i++) {
                if (selectedList[i].UUID !== 0) {
                    temp.push(selectedList[i]);
                }
            }
            var selectedListTemp = [...temp];
            const position = temp.indexOf(removedItem);
            if (position !== -1) {
                selectedListTemp.splice(position, 1);
            }
            variableSet(selectedListTemp);
        }
    };

    return (
        <>
            <Formik
                enableReinitialize
                initialValues={initialValues}
                validationSchema={Yup.object().shape({
                    template_id: Yup.string().required('Template is required')
                })}
                onSubmit={async (values, { setErrors, setSubmitting }) => {
                    setSubmitting(true);
                    if (selectedDevices.length === 0) {
                        setErrors({ device_id: 'Device is required' });
                    } else {
                        var temp = [];
                        for (let i = 0; i < selectedDevices.length; i++) {
                            if (selectedDevices[i].UUID !== 0) {
                                temp.push(selectedDevices[i].UUID);
                            }
                        }
                        console.log(temp);
                        var job = {};
                        job.job_name = 'Create VNF';
                        job.arguments = values;
                        job.arguments.device_id = temp;
                        job.batch_argument = 'device_id';
                        serviceFactoryInstance.dataLoaderService
                            .addJob(ENTITY_NAME_FRONTEND_JOBS, job)
                            .then((data) => {
                                if (data.status) {
                                    setSubmitting(false);
                                    setSuccessSnackbarMessage('Successfully added task');
                                } else {
                                    setSubmitting(false);
                                    setErrors({ submit: data.reason });
                                    setErrorSnackbarMessage('Failed to add task');
                                }
                            })
                            .catch((reason) => {
                                setSubmitting(false);
                                setErrors({ submit: reason });
                                setErrorSnackbarMessage('Failed to add task');
                            });
                    }
                }}
            >
                {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                    <form noValidate onSubmit={handleSubmit}>
                        <Grid container spacing={3}>
                            <Grid item xs={12}>
                                <Stack spacing={1}>
                                    <InputLabel htmlFor="create-vm-form-device_id">Device</InputLabel>
                                    <Multiselect
                                        showCheckbox={true}
                                        options={devicesWithAll} // Options to display in the dropdown
                                        selectedValues={selectedDevices} // Preselected value to persist in dropdown
                                        onSelect={(selectedList, selectedItem) =>
                                            onSelect(selectedList, selectedItem, devices, setSelectedDevices)
                                        } // Function will trigger on select event
                                        onRemove={(selectedList, removedItem) =>
                                            onRemove(selectedList, removedItem, devices, setSelectedDevices)
                                        } // Function will trigger on remove event
                                        displayValue="instance_name" // Property name to display in the dropdown options
                                    />
                                    {errors.device_id && (
                                        <FormHelperText error id="standard-weight-helper-text-create-vm-form-device_id">
                                            {errors.device_id}
                                        </FormHelperText>
                                    )}
                                </Stack>
                            </Grid>
                            <Grid item xs={12}>
                                <Stack spacing={1}>
                                    <InputLabel htmlFor="create-vnf-form-template_id">Template</InputLabel>
                                    <Select
                                        id="create-vnf-form-template_id"
                                        type="text"
                                        value={values.template_id}
                                        name="template_id"
                                        onBlur={handleBlur}
                                        onChange={handleChange}
                                        placeholder="Select template"
                                        fullWidth
                                        error={Boolean(touched.template_id && errors.template_id)}
                                    >
                                        {templates
                                            ? templates.map(
                                                  (template) =>
                                                      template && (
                                                          <MenuItem key={template.UUID} value={template.UUID}>
                                                              {template.instance_name}
                                                          </MenuItem>
                                                      )
                                              )
                                            : ''}
                                    </Select>
                                    {touched.template_id && errors.template_id && (
                                        <FormHelperText error id="standard-weight-helper-text-create-vnf-form-template_id">
                                            {errors.template_id}
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
                                        {'Create'}
                                    </Button>
                                </AnimateButton>
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <AnimateButton>
                                    <Button
                                        onClick={() => {
                                            resetForm();
                                            cleanCloseForm();
                                        }}
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
        </>
    );
};

export default CreateVMForm;
