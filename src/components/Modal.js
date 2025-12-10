import classes from './Modal.module.css';

const Modal = (props) => {
  if (!props.open) return null;
  return (
    <div className={classes.modal_overlay} onClick={props.onClose}>
      <div className={classes.modal_box} onClick={(e) => e.stopPropagation()}>
        <div className={classes.modal_header}>
          <h2>{props.title}</h2>
          <button className={classes.modal_close} onClick={props.onClose}>×</button>
        </div>
        <div className={classes.modal_query}>
          {props.query}
        </div>
      </div>
    </div>
  );
};

export default Modal;
