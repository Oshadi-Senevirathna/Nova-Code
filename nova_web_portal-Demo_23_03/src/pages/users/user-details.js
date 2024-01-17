import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useParams } from 'react-router-dom';
import serviceFactoryInstance from 'framework/services/service-factory';
import { EyeOutlined, EyeInvisibleOutlined } from '@ant-design/icons';
import { ENTITY_NAME_COMPANY, ENTITY_NAME_USERS, ENTITY_NAME_USER_ROLES } from 'framework/caching/entity-cache';
// material-ui
import {
    Card,
    CardContent,
    Button,
    FormHelperText,
    Grid,
    IconButton,
    InputAdornment,
    InputLabel,
    OutlinedInput,
    Stack,
    Checkbox,
    FormControlLabel,
    FormGroup,
    TextField
} from '@mui/material';
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import { Select, MenuItem } from '../../../node_modules/@mui/material/index';
import Multiselect from '../../../node_modules/multiselect-react-dropdown/dist/index';
import './style.css';

// ============================|| FIREBASE - LOGIN ||============================ //

const DetailsPage = ({ title }) => {
    const [initialValues, setInitialValues] = useState({
        instance_name: '',
        email: '',
        first_name: '',
        last_name: '',
        old_pwd: '',
        new_pwd: '',
        new_pwd_re: '',
        company: '',
        roles: ''
    });

    const params = useParams();
    const [edit, setEdit] = useState(false);
    const [showOldPwd, setShowOldPwd] = useState(false);
    const [showNewPwd, setShowNewPwd] = useState(false);
    const [showNewPwdRe, setShowNewPwdRe] = useState(false);
    const [changePwd, setChangePwd] = useState(false);
    const navigate = useNavigate();
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');
    const [companies, setCompanies] = useState([]);
    const [selectedCompany, setSelectedCompany] = useState();
    const [selectedTenants, setSelectedTenants] = useState([]);
    const [tenants, setTenants] = useState([]);
    const [selectedRoles, setSelectedRoles] = useState([]);
    const [roles, setRoles] = useState([]);

    useEffect(() => {
        document.title = title;
    }, []);

    useEffect(() => {
        if (selectedCompany) {
            setTenants(selectedCompany.tenants);
        }
    }, [selectedCompany]);

    useEffect(() => {
        const companiesSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_COMPANY}>summary`).subscribe((data) => {
            if (data) {
                setCompanies(data);
            }
        });
        const rolesSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_USER_ROLES).subscribe((data) => {
            if (data) {
                setRoles(data);

                setInitialValues((prevValues) => ({
                    ...prevValues,
                    roles: data.map((role) => role.UUID)
                }));
            }
        });
        return () => {
            companiesSub.unsubscribe();
            rolesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    useEffect(() => {
        console.log('UUID BEFORE IF CONDITION : ', params.UUID);
        if (params.UUID !== undefined) {
            //edit an existing instance
            serviceFactoryInstance.dataLoaderService.getInstance(params.UUID, ENTITY_NAME_USERS).then((data) => {
                console.log('db values', data);
                if (data.status) {
                    var temp = {};
                    temp['UUID'] = data.instance.UUID;
                    temp['instance_name'] = data.instance.instance_name;
                    temp['email'] = data.instance.email;
                    temp['first_name'] = data.instance.first_name;
                    temp['last_name'] = data.instance.last_name;
                    temp['company'] = data.instance.company;
                    temp['old_pwd'] = '';
                    temp['new_pwd'] = '';
                    temp['new_pwd_re'] = '';
                    console.log('initial values', temp);
                    setInitialValues(temp);
                    if (data.instance.roles && roles.length > 0) {
                        var tempRoles = [];
                        for (let i = 0; i < roles.length; i++) {
                            console.log(roles[i]);
                            if (data.instance.roles.indexOf(roles[i].UUID) > -1) {
                                tempRoles.push(roles[i]);
                            }
                        }
                        setSelectedRoles(tempRoles);
                    }
                    setSelectedTenants(data.instance.tenants ? data.instance.tenants : []);
                    getTenants(data.instance.company);
                }
            });
            setEdit(true);
        }
    }, [params.UUID, roles]);

    const getTenants = (UUID) => {
        serviceFactoryInstance.dataLoaderService.getInstance(UUID, ENTITY_NAME_COMPANY).then((data) => {
            if (data.status) {
                setTenants(data.instance && data.instance.tenants ? data.instance.tenants : []);
            }
        });
    };

    const onSelect = (selectedList, selectedItem, setSelectedValues) => {
        setSelectedValues([...selectedList]);
    };

    const onRemove = (selectedList, removedItem, setSelectedValues) => {
        var selectedListTemp = [...selectedList];
        const position = selectedList.indexOf(removedItem);
        if (position !== -1) {
            selectedListTemp.splice(position, 1);
        }
        setSelectedValues(selectedListTemp);
    };

    return (
        <>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <Card style={{ overflow: 'visible' }}>
                <CardContent>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            var pass = true;
                            var tempRoles = [];
                            for (let i = 0; i < selectedRoles.length; i++) {
                                tempRoles.push(selectedRoles[i].UUID);
                            }

                            var temp = {};
                            temp['instance_name'] = values.instance_name;
                            temp['email'] = values.email;
                            temp['first_name'] = values.first_name;
                            temp['last_name'] = values.last_name;
                            temp['company'] = values.company;
                            temp['tenants'] = selectedTenants;
                            temp['roles'] = tempRoles;
                            // temp['roles'] = values.roles;

                            if (UUID && changePwd) {
                                if (values.new_pwd !== values.new_pwd_re) {
                                    setErrors({ new_pwd_re: 'Passwords should match' });
                                    pass = false;
                                    setSubmitting(false);
                                } else {
                                    temp['old_pwd'] = values.old_pwd;
                                    temp['new_pwd'] = values.new_pwd;
                                }
                            }
                            if (!params.UUID) {
                                temp['pwd'] = values.new_pwd;
                            }
                            if (pass) {
                                console.log(params.UUID);
                                UUID
                                    ? serviceFactoryInstance.authService
                                          .updateUser({ ...temp, UUID: UUID })
                                          .then((data) => {
                                              if (data.status) {
                                                  setSubmitting(false);
                                                  setSuccessSnackbarMessage('Successfully edited the user');
                                              } else {
                                                  setErrors({ submit: data.reason });
                                                  setSubmitting(false);
                                                  setErrorSnackbarMessage('User update failed');
                                              }
                                          })
                                          .catch((reason) => {
                                              setErrors({ submit: reason });
                                              setSubmitting(false);
                                          })
                                    : serviceFactoryInstance.authService
                                          .addUser(temp)
                                          .then((data) => {
                                              if (data.status) {
                                                  setSubmitting(false);
                                                  setSuccessSnackbarMessage('Successfully added the user');
                                              } else {
                                                  setErrors({ submit: data.reason });
                                                  setSubmitting(false);
                                                  setErrorSnackbarMessage('User update failed');
                                              }
                                          })
                                          .catch((reason) => {
                                              setErrors({ submit: reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessage('User update failed');
                                          });
                            }
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-instance_name" className="required-label">
                                                User Name
                                            </InputLabel>
                                            <OutlinedInput
                                                id="user-form-instance_name"
                                                type="text"
                                                required
                                                value={params.UUID}
                                                disabled={edit}
                                                name="instance_name"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter username"
                                                fullWidth
                                                error={Boolean(touched.instance_name && errors.instance_name)}
                                            />
                                            {touched.instance_name && errors.instance_name && (
                                                <FormHelperText error id="standard-weight-helper-text-user-form-instance_name">
                                                    {errors.instance_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-email" className="required-label">
                                                Email
                                            </InputLabel>
                                            <OutlinedInput
                                                id="user-form-email"
                                                type="text"
                                                value={values.email}
                                                name="email"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter email"
                                                fullWidth
                                                error={Boolean(touched.email && errors.email)}
                                                required
                                            />
                                            {touched.email && errors.email && (
                                                <FormHelperText error id="standard-weight-helper-text-user-form-email">
                                                    {errors.email}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-first_name">First Name</InputLabel>
                                            <OutlinedInput
                                                id="user-form-first_name"
                                                type="text"
                                                value={values.first_name}
                                                name="first_name"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter first name"
                                                fullWidth
                                                error={Boolean(touched.first_name && errors.first_name)}
                                            />
                                            {touched.first_name && errors.first_name && (
                                                <FormHelperText error id="standard-weight-helper-text-user-form-first_name">
                                                    {errors.first_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-last_name">Last Name</InputLabel>
                                            <OutlinedInput
                                                id="user-form-last_name"
                                                type="text"
                                                value={values.last_name}
                                                name="last_name"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter last name"
                                                fullWidth
                                                error={Boolean(touched.last_name && errors.last_name)}
                                            />
                                            {touched.last_name && errors.last_name && (
                                                <FormHelperText error id="standard-weight-helper-text-user-form-last_name">
                                                    {errors.last_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    {companies && (
                                        <Grid item xs={12}>
                                            <Stack spacing={1}>
                                                <InputLabel htmlFor="user-form-company" className="required-label">
                                                    Company
                                                </InputLabel>
                                                <Select
                                                    id="user-form-company"
                                                    type="text"
                                                    value={values.company}
                                                    name="company"
                                                    onBlur={handleBlur}
                                                    onChange={(e) => {
                                                        handleChange(e);
                                                        getTenants(e.target.value);
                                                    }}
                                                    placeholder="Select company"
                                                    fullWidth
                                                    error={Boolean(touched.company && errors.company)}
                                                    required
                                                >
                                                    {companies
                                                        ? companies.map(
                                                              (company) =>
                                                                  company && (
                                                                      <MenuItem key={company.UUID} value={company.UUID}>
                                                                          {company.instance_name}
                                                                      </MenuItem>
                                                                  )
                                                          )
                                                        : ''}
                                                </Select>
                                                {touched.company && errors.company && (
                                                    <FormHelperText error id="standard-weight-helper-text-user-form-company">
                                                        {errors.company}
                                                    </FormHelperText>
                                                )}
                                            </Stack>
                                        </Grid>
                                    )}
                                    {tenants && (
                                        <Grid item xs={12}>
                                            <Stack spacing={1}>
                                                <InputLabel htmlFor="user-form-tenants" className="required-label">
                                                    Select Tenants
                                                </InputLabel>
                                                <Multiselect
                                                    required
                                                    showCheckbox={true}
                                                    options={tenants} // Options to display in the dropdown
                                                    selectedValues={selectedTenants} // Preselected value to persist in dropdown
                                                    onSelect={(selectedList, selectedItem) =>
                                                        onSelect(selectedList, selectedItem, setSelectedTenants)
                                                    } // Function will trigger on select event
                                                    onRemove={(selectedList, removedItem) =>
                                                        onRemove(selectedList, removedItem, setSelectedTenants)
                                                    } // Function will trigger on remove event
                                                    displayValue="instance_name" // Property name to display in the dropdown options
                                                />
                                                {touched.tenants && errors.tenants && (
                                                    <FormHelperText error id="standard-weight-helper-text-user-form-tenants">
                                                        {errors.tenants}
                                                    </FormHelperText>
                                                )}
                                            </Stack>
                                        </Grid>
                                    )}
                                    {roles &&
                                        // <Grid item xs={12}>
                                        //     <Stack spacing={1}>
                                        //         <InputLabel htmlFor="user-form-roles">Roles</InputLabel>
                                        //         <Multiselect
                                        //             showCheckbox={true}
                                        //             options={roles} // Options to display in the dropdown
                                        //             selectedValues={selectedRoles} // Preselected value to persist in dropdown
                                        //             onSelect={(selectedList, selectedItem) =>
                                        //                 onSelect(selectedList, selectedItem, setSelectedRoles)
                                        //             } // Function will trigger on select event
                                        //             onRemove={(selectedList, removedItem) =>
                                        //                 onRemove(selectedList, removedItem, setSelectedRoles)
                                        //             } // Function will trigger on remove event
                                        //             displayValue="instance_name" // Property name to display in the dropdown options
                                        //         />
                                        //         {touched.roles && errors.roles && (
                                        //             <FormHelperText error id="standard-weight-helper-text-user-form-roles">
                                        //                 {errors.roles}
                                        //             </FormHelperText>
                                        //         )}
                                        //     </Stack>
                                        // </Grid>

                                        (params.UUID === 'superadmin' ? (
                                            <Grid item xs={12}>
                                                <Stack spacing={1}>
                                                    <InputLabel htmlFor="user-form-roles">Roles</InputLabel>
                                                    <Multiselect
                                                        showCheckbox={true}
                                                        options={roles} // Options to display in the dropdown
                                                        selectedValues={selectedRoles} // Preselected value to persist in dropdown
                                                        onSelect={(selectedList, selectedItem) =>
                                                            onSelect(selectedList, selectedItem, setSelectedRoles)
                                                        } // Function will trigger on select event
                                                        onRemove={(selectedList, removedItem) =>
                                                            onRemove(selectedList, removedItem, setSelectedRoles)
                                                        } // Function will trigger on remove event
                                                        displayValue="instance_name" // Property name to display in the dropdown options
                                                    />
                                                    {touched.roles && errors.roles && (
                                                        <FormHelperText error id="standard-weight-helper-text-user-form-roles">
                                                            {errors.roles}
                                                        </FormHelperText>
                                                    )}
                                                </Stack>
                                            </Grid>
                                        ) : (
                                            <Grid item xs={12}>
                                                <Stack spacing={1}>
                                                    <InputLabel htmlFor="user-form-roles">Roles</InputLabel>
                                                    <TextField
                                                        fullWidth
                                                        InputProps={{
                                                            readOnly: true
                                                        }}
                                                        value={
                                                            values.roles
                                                                ? roles
                                                                      .filter((role) => values.roles.includes(role.UUID))
                                                                      .map((role) => role.instance_name)
                                                                      .join(', ')
                                                                : ''
                                                        }
                                                    />
                                                    {touched.roles && errors.roles && (
                                                        <FormHelperText error id="standard-weight-helper-text-user-form-roles">
                                                            {errors.roles}
                                                        </FormHelperText>
                                                    )}
                                                </Stack>
                                            </Grid>
                                        ))}
                                    {params.UUID && (
                                        <Grid item xs={12}>
                                            <Stack spacing={1}>
                                                <FormGroup>
                                                    <FormControlLabel
                                                        control={
                                                            <Checkbox
                                                                checked={changePwd}
                                                                onChange={() => {
                                                                    if (changePwd) {
                                                                        values.old_pwd = '';
                                                                        values.new_pwd = '';
                                                                        values.new_pwd_re = '';
                                                                    }
                                                                    setChangePwd(!changePwd);
                                                                }}
                                                            />
                                                        }
                                                        label="Change password"
                                                    />
                                                </FormGroup>
                                                {changePwd && (
                                                    <>
                                                        <Grid item xs={12}>
                                                            <Stack spacing={1}>
                                                                <InputLabel htmlFor="user-form-old-pwd">Old Password</InputLabel>
                                                                <OutlinedInput
                                                                    id="user-form-old-pwd"
                                                                    type={showOldPwd ? 'text' : 'password'}
                                                                    value={values.old_pwd}
                                                                    name="old_pwd"
                                                                    onBlur={handleBlur}
                                                                    onChange={handleChange}
                                                                    placeholder="Enter old password"
                                                                    fullWidth
                                                                    error={Boolean(touched.old_pwd && errors.old_pwd)}
                                                                    endAdornment={
                                                                        <InputAdornment position="end">
                                                                            <IconButton
                                                                                aria-label="toggle password visibility"
                                                                                onClick={() => setShowOldPwd(!showOldPwd)}
                                                                            >
                                                                                {showOldPwd ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                            </IconButton>
                                                                        </InputAdornment>
                                                                    }
                                                                />
                                                                {touched.old_pwd && errors.old_pwd && (
                                                                    <FormHelperText
                                                                        error
                                                                        id="standard-weight-helper-text-user-form-old-pwd"
                                                                    >
                                                                        {errors.old_pwd}
                                                                    </FormHelperText>
                                                                )}
                                                            </Stack>
                                                        </Grid>
                                                        <Grid item xs={12}>
                                                            <Stack spacing={1}>
                                                                <InputLabel htmlFor="user-form-new-pwd">New Password</InputLabel>
                                                                <OutlinedInput
                                                                    id="user-form-new-pwd"
                                                                    type={showNewPwd ? 'text' : 'password'}
                                                                    value={values.new_pwd}
                                                                    name="new_pwd"
                                                                    onBlur={handleBlur}
                                                                    onChange={handleChange}
                                                                    placeholder="Enter new password"
                                                                    fullWidth
                                                                    error={Boolean(touched.new_pwd && errors.new_pwd)}
                                                                    endAdornment={
                                                                        <InputAdornment position="end">
                                                                            <IconButton
                                                                                aria-label="toggle password visibility"
                                                                                onClick={() => setShowNewPwd(!showNewPwd)}
                                                                            >
                                                                                {showNewPwd ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                            </IconButton>
                                                                        </InputAdornment>
                                                                    }
                                                                />
                                                                {touched.new_pwd && errors.new_pwd && (
                                                                    <FormHelperText
                                                                        error
                                                                        id="standard-weight-helper-text-user-form-new-pwd"
                                                                    >
                                                                        {errors.new_pwd}
                                                                    </FormHelperText>
                                                                )}
                                                            </Stack>
                                                        </Grid>
                                                        <Grid item xs={12}>
                                                            <Stack spacing={1}>
                                                                <InputLabel htmlFor="user-form-new-pwd-re">
                                                                    Re-enter New Password
                                                                </InputLabel>
                                                                <OutlinedInput
                                                                    id="user-form-new-pwd-re"
                                                                    type={showNewPwdRe ? 'text' : 'password'}
                                                                    value={values.new_pwd_re}
                                                                    name="new_pwd_re"
                                                                    onBlur={handleBlur}
                                                                    onChange={handleChange}
                                                                    placeholder="Enter new password"
                                                                    fullWidth
                                                                    error={Boolean(touched.new_pwd_re && errors.new_pwd_re)}
                                                                    endAdornment={
                                                                        <InputAdornment position="end">
                                                                            <IconButton
                                                                                aria-label="toggle password visibility"
                                                                                onClick={() => setShowNewPwdRe(!showNewPwdRe)}
                                                                            >
                                                                                {showNewPwdRe ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                            </IconButton>
                                                                        </InputAdornment>
                                                                    }
                                                                />
                                                                {touched.new_pwd_re && errors.new_pwd_re && (
                                                                    <FormHelperText
                                                                        error
                                                                        id="standard-weight-helper-text-user-form-new-pwd-re"
                                                                    >
                                                                        {errors.new_pwd_re}
                                                                    </FormHelperText>
                                                                )}
                                                            </Stack>
                                                        </Grid>
                                                    </>
                                                )}
                                            </Stack>
                                        </Grid>
                                    )}

                                    {!params.UUID && (
                                        <Grid item xs={12}>
                                            <Stack spacing={1}>
                                                <Grid item xs={12}>
                                                    <Stack spacing={1}>
                                                        <InputLabel htmlFor="user-form-new-pwd">Password</InputLabel>
                                                        <OutlinedInput
                                                            id="user-form-new-pwd"
                                                            type={showNewPwd ? 'text' : 'password'}
                                                            value={values.new_pwd}
                                                            name="new_pwd"
                                                            onBlur={handleBlur}
                                                            onChange={handleChange}
                                                            placeholder="Enter new password"
                                                            fullWidth
                                                            error={Boolean(touched.new_pwd && errors.new_pwd)}
                                                            endAdornment={
                                                                <InputAdornment position="end">
                                                                    <IconButton
                                                                        aria-label="toggle password visibility"
                                                                        onClick={() => setShowNewPwd(!showNewPwd)}
                                                                    >
                                                                        {showNewPwd ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                    </IconButton>
                                                                </InputAdornment>
                                                            }
                                                        />
                                                        {touched.new_pwd && errors.new_pwd && (
                                                            <FormHelperText error id="standard-weight-helper-text-user-form-new-pwd">
                                                                {errors.new_pwd}
                                                            </FormHelperText>
                                                        )}
                                                    </Stack>
                                                </Grid>
                                                <Grid item xs={12}>
                                                    <Stack spacing={1}>
                                                        <InputLabel htmlFor="user-form-new-pwd-re">Re-enter Password</InputLabel>
                                                        <OutlinedInput
                                                            id="user-form-new-pwd-re"
                                                            type={showNewPwdRe ? 'text' : 'password'}
                                                            value={values.new_pwd_re}
                                                            name="new_pwd_re"
                                                            onBlur={handleBlur}
                                                            onChange={handleChange}
                                                            placeholder="Enter new password"
                                                            fullWidth
                                                            error={Boolean(touched.new_pwd_re && errors.new_pwd_re)}
                                                            endAdornment={
                                                                <InputAdornment position="end">
                                                                    <IconButton
                                                                        aria-label="toggle password visibility"
                                                                        onClick={() => setShowNewPwdRe(!showNewPwdRe)}
                                                                    >
                                                                        {showNewPwdRe ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                    </IconButton>
                                                                </InputAdornment>
                                                            }
                                                        />
                                                        {touched.new_pwd_re && errors.new_pwd_re && (
                                                            <FormHelperText error id="standard-weight-helper-text-user-form-new-pwd-re">
                                                                {errors.new_pwd_re}
                                                            </FormHelperText>
                                                        )}
                                                    </Stack>
                                                </Grid>
                                            </Stack>
                                        </Grid>
                                    )}
                                    {errors.submit && (
                                        <Grid item xs={12}>
                                            <FormHelperText error>{errors.submit}</FormHelperText>
                                        </Grid>
                                    )}
                                    {params.UUID && (
                                        <Grid item xs={12} md={6}>
                                            <AnimateButton>
                                                <Button
                                                    disableElevation
                                                    disabled={isSubmitting}
                                                    fullWidth
                                                    size="large"
                                                    variant="contained"
                                                    color="primary"
                                                    type="submit"
                                                >
                                                    Save
                                                </Button>
                                            </AnimateButton>
                                        </Grid>
                                    )}
                                    {!params.UUID && (
                                        <>
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
                                                        {!params.UUID ? 'Add' : 'Save'}
                                                    </Button>
                                                </AnimateButton>
                                            </Grid>
                                        </>
                                    )}
                                    <Grid item xs={12} md={6}>
                                        <AnimateButton>
                                            <Button
                                                onClick={() => {
                                                    resetForm();
                                                    /* editUnset(); */
                                                    /* if (!params.UUID) {
                                                                navigate(`/users`);
                                                            } */
                                                    navigate(`/users`);
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
                </CardContent>
            </Card>
        </>
    );
};

export default DetailsPage;
